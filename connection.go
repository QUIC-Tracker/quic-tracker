package quictracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
	"github.com/mpiraux/pigotls"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"unsafe"
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	UseIPv6        bool
	Host           *net.UDPAddr

	Tls           *pigotls.Connection
	TLSTPHandler  *TLSTransportParameterHandler

	KeyPhaseIndex  uint
	SpinBit   	   SpinBit
	LastSpinNumber PacketNumber

	CryptoStates   map[EncryptionLevel]*CryptoState

	ExporterSecret []byte

	ReceivedPacketHandler func([]byte, unsafe.Pointer)
	SentPacketHandler     func([]byte, unsafe.Pointer)

	CryptoStreams       CryptoStreams  // TODO: It should be a parent class without closing states
	Streams             Streams

	IncomingPackets           Broadcaster //type: Packet
	OutgoingPackets           Broadcaster //type: Packet
	IncomingPayloads          Broadcaster //type: IncomingPayload
	UnprocessedPayloads       Broadcaster //type: UnprocessedPayload
	EncryptionLevelsAvailable Broadcaster //type: DirectionalEncryptionLevel
	FrameQueue                Broadcaster //type: QueuedFrame
	TransportParameters       Broadcaster //type: QuicTransportParameters

	PreparePacket 			  Broadcaster //type: EncryptionLevel
	StreamInput               Broadcaster //type: StreamInput

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

	PacketNumber           map[PNSpace]PacketNumber // Stores the next PN to be sent
	LargestPNsReceived     map[PNSpace]PacketNumber // Stores the largest PN received
	LargestPNsAcknowledged map[PNSpace]PacketNumber // Stores the largest PN we have sent that were acknowledged by the peer

	MinRTT             uint64
	SmoothedRTT        uint64
	RTTVar             uint64

	AckQueue             map[PNSpace][]PacketNumber // Stores the packet numbers to be acked TODO: This should be a channel actually
	Logger               *log.Logger
}
func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber(space PNSpace) PacketNumber {  // TODO: This should be thread safe
	pn := c.PacketNumber[space]
	c.PacketNumber[space]++
	return pn
}
func (c *Connection) SendPacket(packet Packet, level EncryptionLevel) {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		c.Logger.Printf("Sending packet {type=%s, number=%d}\n", packet.Header().PacketType().String(), packet.Header().PacketNumber())
		cryptoState := c.CryptoStates[level]

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

		c.UdpConnection.Write(packetBytes)

		if c.SentPacketHandler != nil {
			c.SentPacketHandler(packet.Encode(packet.EncodePayload()), packet.Pointer())
		}
		c.OutgoingPackets.Submit(packet)
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
		c.CryptoStates[EncryptionLevel0RTT] = NewProtectedCryptoState(c.Tls, nil, c.Tls.ZeroRTTSecret())
		c.EncryptionLevelsAvailable.Submit(DirectionalEncryptionLevel{EncryptionLevel0RTT, false})
	}

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, cryptoFrame)
	payloadLen := len(initialPacket.EncodePayload())
	paddingLength := initialLength - (len(initialPacket.header.Encode()) + int(VarIntLen(uint64(payloadLen))) + payloadLen + c.CryptoStates[EncryptionLevelInitial].Write.Overhead())
	for i := 0; i < paddingLength; i++ {
		initialPacket.Frames = append(initialPacket.Frames, new(PaddingFrame))
	}

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
	c.TransitionTo(QuicVersion, QuicALPNToken)
	return nil
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
	c.TLSTPHandler = NewTLSTransportParameterHandler()
	c.Version = version
	c.ALPN = ALPN
	c.Tls = pigotls.NewConnection(c.ServerName, c.ALPN, c.ResumptionTicket)
	c.PacketNumber = make(map[PNSpace]PacketNumber)
	c.LargestPNsReceived = make(map[PNSpace]PacketNumber)
	c.LargestPNsAcknowledged = make(map[PNSpace]PacketNumber)
	c.AckQueue = make(map[PNSpace][]PacketNumber)
	for _, space := range []PNSpace{PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData} {
		c.PacketNumber[space] = 0
		c.AckQueue[space] = nil
	}

	c.CryptoStates = make(map[EncryptionLevel]*CryptoState)
	c.CryptoStreams = make(map[PNSpace]*Stream)
	c.CryptoStates[EncryptionLevelInitial] = NewInitialPacketProtection(c)
	c.Streams = Streams{streams: make(map[uint64]*Stream), lock: &sync.Mutex{}, input: &c.StreamInput}
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint16, reasonPhrase string) {
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
	c.EncryptionLevelsAvailable = NewBroadcaster(10)
	c.FrameQueue = NewBroadcaster(1000)
	c.TransportParameters = NewBroadcaster(10)
	c.ConnectionClosed = make(chan bool, 1)
	c.ConnectionRestart = make(chan bool, 1)
	c.ConnectionRestarted = make(chan bool, 1)
	c.PreparePacket = NewBroadcaster(1000)
	c.StreamInput = NewBroadcaster(1000)

	c.Logger = log.New(os.Stderr, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.OriginalDestinationCID)), log.Lshortfile)

	c.TransitionTo(version, ALPN)

	return c
}