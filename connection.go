package quictracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"github.com/mpiraux/pigotls"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	UseIPv6       bool
	Host          *net.UDPAddr
	InterfaceMTU  int

	Tls           *pigotls.Connection
	TLSTPHandler  *TLSTransportParameterHandler

	KeyPhaseIndex  uint
	SpinBit   	   SpinBit
	LastSpinNumber PacketNumber

	CryptoStateLock sync.Locker
	CryptoStates   map[EncryptionLevel]*CryptoState

	ReceivedPacketHandler func([]byte, unsafe.Pointer)
	SentPacketHandler     func([]byte, unsafe.Pointer)

	CryptoStreams       CryptoStreams  // TODO: It should be a parent class without closing states
	Streams             Streams

	IncomingPackets     Broadcaster //type: Packet
	OutgoingPackets     Broadcaster //type: Packet
	IncomingPayloads    Broadcaster //type: IncomingPayload
	UnprocessedPayloads Broadcaster //type: UnprocessedPayload
	EncryptionLevels    Broadcaster //type: DirectionalEncryptionLevel
	FrameQueue          Broadcaster //type: QueuedFrame
	TransportParameters Broadcaster //type: QuicTransportParameters

	PreparePacket 			  Broadcaster //type: EncryptionLevel
	SendPacket 			      Broadcaster //type: PacketToSend
	StreamInput               Broadcaster //type: StreamInput
	PacketAcknowledged        Broadcaster //type: PacketAcknowledged

	ConnectionClosed 		  chan bool
	ConnectionRestart 	  	  chan bool // Triggered when receiving a Retry or a VN packet
	ConnectionRestarted 	  chan bool

	OriginalDestinationCID ConnectionID
	SourceCID              ConnectionID
	DestinationCID         ConnectionID
	Version                uint32
	ALPN                   string

	Token            []byte
	ResumptionTicket []byte

	PacketNumberLock       sync.Locker
	PacketNumber           map[PNSpace]PacketNumber // Stores the next PN to be sent
	LargestPNsReceived     map[PNSpace]PacketNumber // Stores the largest PN received
	LargestPNsAcknowledged map[PNSpace]PacketNumber // Stores the largest PN we have sent that were acknowledged by the peer

	MinRTT             uint64
	SmoothedRTT        uint64
	RTTVar             uint64

	AckQueue             map[PNSpace][]PacketNumber // Stores the packet numbers to be acked TODO: This should be a channel actually
	Logger               *log.Logger
	QLog 				 qlog.QLog
	QLogTrace			 *qlog.Trace
	QLogEvents			 chan *qlog.Event
}
func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber(space PNSpace) PacketNumber {  // TODO: This should be thread safe
	c.PacketNumberLock.Lock()
	pn := c.PacketNumber[space]
	c.PacketNumber[space]++
	c.PacketNumberLock.Unlock()
	return pn
}
func (c *Connection) CryptoState(level EncryptionLevel) *CryptoState {
	c.CryptoStateLock.Lock()
	cs, ok := c.CryptoStates[level]
	c.CryptoStateLock.Unlock()
	if ok {
		return cs
	}
	return nil
}
func (c *Connection) EncodeAndEncrypt(packet Packet, level EncryptionLevel) []byte {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		cryptoState := c.CryptoState(level)

		payload := packet.EncodePayload()
		if h, ok := packet.Header().(*LongHeader); ok {
			h.Length = NewVarInt(uint64(h.TruncatedPN().Length + len(payload) + cryptoState.Write.Overhead()))
		}

		header := packet.EncodeHeader()
		protectedPayload := cryptoState.Write.Encrypt(payload, uint64(packet.Header().PacketNumber()), header)
		packetBytes := append(header, protectedPayload...)

		firstByteMask := byte(0x1F)
		if packet.Header().PacketType() != ShortHeaderPacket {
			firstByteMask = 0x0F
		}
		sample, pnOffset := GetPacketSample(packet.Header(), packetBytes)
		mask := cryptoState.HeaderWrite.Encrypt(sample, make([]byte, 5, 5))
		packetBytes[0] ^= mask[0] & firstByteMask

		for i := 0; i < packet.Header().TruncatedPN().Length; i++ {
			packetBytes[pnOffset+i] ^= mask[1+i]
		}

		return packetBytes
	default:
		// Clients do not send cleartext packets
	}
	return nil
}

func (c *Connection) PacketWasSent(packet Packet) {
	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.Encode(packet.EncodePayload()), packet.Pointer())
	}
	c.OutgoingPackets.Submit(packet)
}
func (c *Connection) DoSendPacket(packet Packet, level EncryptionLevel) {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		c.Logger.Printf("Sending packet {type=%s, number=%d}\n", packet.Header().PacketType().String(), packet.Header().PacketNumber())

		packetBytes := c.EncodeAndEncrypt(packet, level)
		c.UdpConnection.Write(packetBytes)
		packet.SetSendContext(PacketContext{Timestamp: time.Now(), RemoteAddr: c.UdpConnection.RemoteAddr(), DatagramSize: uint16(len(packetBytes)), PacketSize: uint16(len(packetBytes))})

		c.PacketWasSent(packet)
	default:
		// Clients do not send cleartext packets
	}
}
func (c *Connection) GetInitialPacket() *InitialPacket {
	extensionData, err := c.TLSTPHandler.GetExtensionData()
	if err != nil {
		println(err)
		return nil
	}
	c.Tls.SetQUICTransportParameters(extensionData)

	tlsOutput, notComplete, err := c.Tls.HandleMessage(nil, pigotls.EpochInitial)
	if err != nil || !notComplete {
		println(err.Error())
		return nil
	}
	clientHello := tlsOutput[0].Data
	cryptoFrame := NewCryptoFrame(c.CryptoStreams.Get(PNSpaceInitial), clientHello)

	if len(c.Tls.ZeroRTTSecret()) > 0 {
		c.Logger.Printf("0-RTT secret is available, installing crypto state")
		c.CryptoStateLock.Lock()
		c.CryptoStates[EncryptionLevel0RTT] = NewProtectedCryptoState(c.Tls, nil, c.Tls.ZeroRTTSecret())
		c.CryptoStateLock.Unlock()
		c.EncryptionLevels.Submit(DirectionalEncryptionLevel{EncryptionLevel: EncryptionLevel0RTT, Read: false, Available: true})
	}

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, cryptoFrame)
	initialPacket.PadTo(initialLength - c.CryptoState(EncryptionLevelInitial).Write.Overhead())

	return initialPacket
}
func (c *Connection) ProcessVersionNegotation(vn *VersionNegotiationPacket) error {
	var version uint32
	for _, v := range vn.SupportedVersions {
		if v >= MinimumVersion && v <= MaximumVersion {
			version = uint32(v)
		}
	}
	if version == 0 {
		c.Logger.Println("No appropriate version was found in the VN packet")
		c.Logger.Printf("Versions received: %v\n", vn.SupportedVersions)
		return errors.New("no appropriate version found")
	}
	QuicVersion = version
	QuicALPNToken = fmt.Sprintf("%s-%02d", strings.Split(c.ALPN, "-")[0], version & 0xff)
	_, err := rand.Read(c.DestinationCID)
	c.TransitionTo(QuicVersion, QuicALPNToken)
	return err
}
func (c *Connection) GetAckFrame(space PNSpace) *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.AckQueue[space]))
	packetNumbers := make([]PacketNumber, 0, len(c.AckQueue[space]))
	if len(c.AckQueue[space]) > 0 {
		last := c.AckQueue[space][0]
		packetNumbers = append(packetNumbers, last)
		for _, i := range c.AckQueue[space] {
			if i != last {
				last = i
				packetNumbers = append(packetNumbers, i)
			}
		}
	}

	if len(packetNumbers) == 0 {
		return nil
	}

	frame := new(AckFrame)
	frame.AckRanges = make([]AckRange, 0, 255)
	frame.LargestAcknowledged = packetNumbers[0]

	previous := frame.LargestAcknowledged
	ackBlock := AckRange{}
	for _, number := range packetNumbers[1:] {
		if previous - number == 1 {
			ackBlock.AckRange++
		} else {
			frame.AckRanges = append(frame.AckRanges, ackBlock)
			ackBlock = AckRange{uint64(previous) - uint64(number) - 2, 0}
		}
		previous = number
	}
	frame.AckRanges = append(frame.AckRanges, ackBlock)
	if len(frame.AckRanges) > 0 {
		frame.AckRangeCount = uint64(len(frame.AckRanges) - 1)
	}
	return frame
}
func (c *Connection) TransitionTo(version uint32, ALPN string) {
	c.TLSTPHandler = NewTLSTransportParameterHandler(c.SourceCID)
	c.Version = version
	c.ALPN = ALPN
	c.Tls = pigotls.NewConnection(c.ServerName, c.ALPN, c.ResumptionTicket)
	c.PacketNumberLock = &sync.Mutex{}
	c.PacketNumber = make(map[PNSpace]PacketNumber)
	c.LargestPNsReceived = make(map[PNSpace]PacketNumber)
	c.LargestPNsAcknowledged = make(map[PNSpace]PacketNumber)
	c.AckQueue = make(map[PNSpace][]PacketNumber)
	for _, space := range []PNSpace{PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData} {
		c.PacketNumber[space] = 0
		c.AckQueue[space] = nil
	}

	c.CryptoStateLock = &sync.Mutex{}
	c.CryptoStateLock.Lock()
	c.CryptoStates = make(map[EncryptionLevel]*CryptoState)
	c.CryptoStreams = make(map[PNSpace]*Stream)
	c.CryptoStates[EncryptionLevelInitial] = NewInitialPacketProtection(c)
	c.CryptoStateLock.Unlock()
	c.Streams = Streams{streams: make(map[uint64]*Stream), lock: &sync.Mutex{}, input: &c.StreamInput}
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint64, reasonPhrase string) {
	if quicLayer {
		c.FrameQueue.Submit(QueuedFrame{&ConnectionCloseFrame{errCode,0, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	} else {
		c.FrameQueue.Submit(QueuedFrame{&ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	}
}
func (c *Connection) SendHTTP09GETRequest(path string, streamID uint64) {
	c.Streams.Send(streamID, []byte(fmt.Sprintf("GET %s\r\n", path)), true)
}
func (c *Connection) Close() {
	c.Tls.Close()
	c.UdpConnection.Close()
}
func EstablishUDPConnection(addr *net.UDPAddr) (*net.UDPConn, error) {
	udpConn, err := net.DialUDP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	return udpConn, nil
}
func NewDefaultConnection(address string, serverName string, resumptionTicket []byte, useIPv6 bool, preferredALPN string, negotiateHTTP3 bool) (*Connection, error) {
	scid := make([]byte, 8, 8)
	dcid := make([]byte, 8, 8)
	rand.Read(scid)
	rand.Read(dcid)

	var network string
	if useIPv6 {
		network = "udp6"
	} else {
		network = "udp4"
	}

	udpAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	udpConn, err := EstablishUDPConnection(udpAddr)
	if err != nil {
		return nil, err
	}

	var c *Connection
	if negotiateHTTP3 {
		c = NewConnection(serverName, QuicVersion, QuicH3ALPNToken, scid, dcid, udpConn, resumptionTicket)
	} else {
		QuicALPNToken = fmt.Sprintf("%s-%02d", preferredALPN, QuicVersion & 0xff)
		c = NewConnection(serverName, QuicVersion, QuicALPNToken, scid, dcid, udpConn, resumptionTicket)
	}

	var headerOverhead = 8
	if useIPv6 {
		headerOverhead += 40
	} else {
		headerOverhead += 20
	}

	lAddr := udpConn.LocalAddr().(*net.UDPAddr)
	itfs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

findMTU:
	for _, e := range itfs {
		addrs , err := e.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			switch ipNet := a.(type) {
			case *net.IPNet:
				if ipNet.IP.Equal(lAddr.IP) {
					c.InterfaceMTU = e.MTU
					c.TLSTPHandler.MaxPacketSize = uint64(c.InterfaceMTU - headerOverhead)
					break findMTU
				}
			}
		}
	}

	c.UseIPv6 = useIPv6
	c.Host = udpAddr
	return c, nil
}

func NewConnection(serverName string, version uint32, ALPN string, SCID []byte, DCID[]byte , udpConn *net.UDPConn, resumptionTicket []byte) *Connection {
	c := new(Connection)
	c.ServerName = serverName
	c.UdpConnection = udpConn
	c.SourceCID = SCID
	c.DestinationCID = DCID
	c.OriginalDestinationCID = DCID

	c.ResumptionTicket = resumptionTicket

	c.IncomingPackets = NewBroadcaster(1000)
	c.OutgoingPackets = NewBroadcaster(1000)
	c.IncomingPayloads = NewBroadcaster(1000)
	c.UnprocessedPayloads = NewBroadcaster(1000)
	c.EncryptionLevels = NewBroadcaster(10)
	c.FrameQueue = NewBroadcaster(1000)
	c.TransportParameters = NewBroadcaster(10)
	c.ConnectionClosed = make(chan bool, 1)
	c.ConnectionRestart = make(chan bool, 1)
	c.ConnectionRestarted = make(chan bool, 1)
	c.PreparePacket = NewBroadcaster(1000)
	c.SendPacket = NewBroadcaster(1000)
	c.StreamInput = NewBroadcaster(1000)
	c.PacketAcknowledged = NewBroadcaster(1000)

	c.QLog.Version = "draft-01"
	c.QLog.Description = "QUIC-Tracker"
	if len(GitCommit()) > 0 {
		c.QLog.Description += " commit " + GitCommit()
	}
	c.QLogTrace = &qlog.Trace{}
	c.QLog.Traces = append(c.QLog.Traces, c.QLogTrace)

	c.QLogTrace.VantagePoint.Name = "QUIC-Tracker"
	c.QLogTrace.VantagePoint.Type = "client"
	c.QLogTrace.Description = fmt.Sprintf("Connection to %s (%s), using version %08x and alpn %s", serverName, udpConn.RemoteAddr().String(), version, ALPN)
	c.QLogTrace.ReferenceTime = time.Now()
	c.QLogTrace.Configuration.TimeUnits = qlog.TimeUnitsString

	c.QLogTrace.CommonFields = make(map[string]interface{})
	c.QLogTrace.CommonFields["ODCID"] = hex.EncodeToString(c.OriginalDestinationCID)
	c.QLogTrace.CommonFields["group_id"] = c.QLogTrace.CommonFields["ODCID"]
	c.QLogTrace.CommonFields["reference_time"] = c.QLogTrace.ReferenceTime.UnixNano() / int64(qlog.TimeUnits)
	c.QLogTrace.EventFields = qlog.DefaultEventFields()
	c.QLogEvents = make(chan *qlog.Event, 1000)

	go func() {
		for e := range c.QLogEvents {
			c.QLogTrace.Add(e)
		}
	}()

	c.Logger = log.New(os.Stderr, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.OriginalDestinationCID)), log.Lshortfile)

	c.TransitionTo(version, ALPN)

	return c
}