package quictracker

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
	"github.com/dustin/go-broadcast"
	"github.com/mpiraux/pigotls"
	"log"
	"net"
	"os"
	"sort"
	"unsafe"
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	UseIPv6        bool
	Host           *net.UDPAddr

	Tls           *pigotls.Connection
	TLSTPHandler  *TLSTransportParameterHandler
	KeyPhaseIndex uint

	CryptoStates   map[EncryptionLevel]*CryptoState

	ExporterSecret []byte

	ReceivedPacketHandler func([]byte, unsafe.Pointer)
	SentPacketHandler     func([]byte, unsafe.Pointer)

	CryptoStreams       CryptoStreams  // TODO: It should be a parent class without closing states
	Streams             Streams

	IncomingPackets           broadcast.Broadcaster //type: Packet
	OutgoingPackets           broadcast.Broadcaster //type: Packet
	IncomingPayloads          broadcast.Broadcaster //type: []byte
	UnprocessedPayloads       broadcast.Broadcaster //type: UnprocessedPayload
	EncryptionLevelsAvailable broadcast.Broadcaster //type: DirectionalEncryptionLevel
	FrameQueue                broadcast.Broadcaster //type: QueuedFrame

	OriginalDestinationCID ConnectionID
	SourceCID              ConnectionID
	DestinationCID         ConnectionID
	Version                uint32

	Token            []byte
	ResumptionTicket []byte

	PacketNumber           map[PNSpace]PacketNumber // Stores the next PN to be sent
	LargestPNsReceived     map[PNSpace]PacketNumber // Stores the largest PN received
	LargestPNsAcknowledged map[PNSpace]PacketNumber // Stores the largest PN we have sent that were acknowledged by the peer

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
	QuicVersion, QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
	c.TransitionTo(QuicVersion, QuicALPNToken)
	return nil
}
func (c *Connection) GetAckFrame(space PNSpace) *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.AckQueue[space]))
	packetNumbers := c.AckQueue[space]
	if len(packetNumbers) == 0 {
		return nil
	}
	frame := new(AckFrame)
	frame.AckBlocks = make([]AckBlock, 0, 255)
	frame.LargestAcknowledged = packetNumbers[0]

	previous := frame.LargestAcknowledged
	ackBlock := AckBlock{}
	for _, number := range packetNumbers[1:] {
		if previous - number == 1 {
			ackBlock.Block++
		} else {
			frame.AckBlocks = append(frame.AckBlocks, ackBlock)
			ackBlock = AckBlock{uint64(previous) - uint64(number) - 2, 0}
		}
		previous = number
	}
	frame.AckBlocks = append(frame.AckBlocks, ackBlock)
	if len(frame.AckBlocks) > 0 {
		frame.AckBlockCount = uint64(len(frame.AckBlocks) - 1)
	}
	return frame
}
func (c *Connection) TransitionTo(version uint32, ALPN string) {
	var prevVersion uint32
	if c.Version == 0 {
		prevVersion = QuicVersion
	} else {
		prevVersion = c.Version
	}
	c.TLSTPHandler = NewTLSTransportParameterHandler(version, prevVersion)
	c.Version = version
	c.Tls = pigotls.NewConnection(c.ServerName, ALPN, c.ResumptionTicket)
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
	c.Streams = make(map[uint64]*Stream)
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint16, reasonPhrase string) {
	if quicLayer {
		c.FrameQueue.Submit(QueuedFrame{&ConnectionCloseFrame{errCode,0, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	} else {
		c.FrameQueue.Submit(QueuedFrame{&ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase}, EncryptionLevelBest})
	}
}
func (c *Connection) SendHTTPGETRequest(path string, streamID uint64) {
	c.FrameQueue.Submit(QueuedFrame{NewStreamFrame(streamID, c.Streams.Get(streamID), []byte(fmt.Sprintf("GET %s\r\n", path)), true), EncryptionLevelBest})
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
func NewDefaultConnection(address string, serverName string, resumptionTicket []byte, useIPv6 bool) (*Connection, error) {
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

	c := NewConnection(serverName, QuicVersion, QuicALPNToken, scid, dcid, udpConn, resumptionTicket)
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

	c.IncomingPackets = broadcast.NewBroadcaster(1000)
	c.OutgoingPackets = broadcast.NewBroadcaster(1000)
	c.IncomingPayloads = broadcast.NewBroadcaster(1000)
	c.UnprocessedPayloads = broadcast.NewBroadcaster(1000)
	c.EncryptionLevelsAvailable = broadcast.NewBroadcaster(10)
	c.FrameQueue = broadcast.NewBroadcaster(1000)

	c.Logger = log.New(os.Stderr, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.OriginalDestinationCID)), log.Lshortfile)

	c.TransitionTo(version, ALPN)

	return c
}