package masterthesis

import (
	"github.com/bifurcation/mint"
	"crypto/rand"
	"encoding/binary"
	"net"
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"time"
	"os"
	"fmt"
	"crypto"
	"errors"
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	tlsBuffer     *connBuffer
	tls           *mint.Conn
	TLSTPHandler  *TLSTransportParameterHandler

	Cleartext        *CryptoState
	protected        *CryptoState
	cipherSuite		 *mint.CipherSuiteParams

	ReceivedPacketHandler func([]byte)
	SentPacketHandler     func([]byte)

	Streams              map[uint64]*Stream
	ConnectionId         uint64
	PacketNumber         uint64
	expectedPacketNumber uint64
	Version              uint32
	omitConnectionId     bool
	ackQueue             []uint64  // Stores the packet numbers to be acked
	receivedPackets      uint64  // TODO: Implement proper ACK mechanism

	useIPv6	bool
}
func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber() uint64 {
	c.PacketNumber++
	return c.PacketNumber
}
func (c *Connection) sendHandshakeProtectedPacket(packet Packet) {
	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.encode(packet.encodePayload()))
	}
	header := packet.encodeHeader()
	protectedPayload := c.Cleartext.Write.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), packet.encodePayload(), header)
	finalPacket := make([]byte, 0, 1500)  // TODO Find a proper upper bound on total packet size
	finalPacket = append(finalPacket, header...)
	finalPacket = append(finalPacket, protectedPayload...)
	c.UdpConnection.Write(finalPacket)
}
func (c *Connection) SendProtectedPacket(packet Packet) {
	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.encode(packet.encodePayload()))
	}
	header := packet.encodeHeader()
	protectedPayload := c.protected.Write.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), packet.encodePayload(), header)
	finalPacket := make([]byte, 0, 1500)  // TODO Find a proper upper bound on total packet size
	finalPacket = append(finalPacket, header...)
	finalPacket = append(finalPacket, protectedPayload...)
	c.UdpConnection.Write(finalPacket)
}
func (c *Connection) SendInitialPacket() {
	c.tls.Handshake()
	handshakeResult := c.tlsBuffer.getOutput()
	handshakeFrame := NewStreamFrame(0, c.Streams[0], handshakeResult, false)

	var initialLength int
	if c.useIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(make([]StreamFrame, 0, 1), make([]PaddingFrame, 0, initialLength), c)
	initialPacket.streamFrames = append(initialPacket.streamFrames, *handshakeFrame)
	paddingLength := initialLength - (LongHeaderSize + len(initialPacket.encodePayload()) + c.Cleartext.Write.Overhead())
	for i := 0; i < paddingLength; i++ {
		initialPacket.padding = append(initialPacket.padding, *new(PaddingFrame))
	}

	c.sendHandshakeProtectedPacket(initialPacket)
}
func (c *Connection) ProcessServerHello(packet *HandshakePacket) (bool, error) { // Returns whether or not the TLS Handshake should continue
	c.ConnectionId = packet.header.ConnectionId() // see https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.6

	var serverData []byte
	for _, frame := range packet.StreamFrames {
		serverData = append(serverData, frame.StreamData...)
	}

	var clearTextPacket *HandshakePacket
	ackFrame := c.GetAckFrame()

	c.tlsBuffer.input(serverData)

	for {
		alert := c.tls.Handshake()
		switch alert {
		case mint.AlertNoAlert:
			tlsOutput := c.tlsBuffer.getOutput()

			state := c.tls.ConnectionState()
			if state.HandshakeState == mint.StateClientConnected {
				// TODO: Check negotiated ALPN ?
				c.cipherSuite = &state.CipherSuite
				c.protected = NewProtectedCryptoState(c)

				outputFrame := NewStreamFrame(0, c.Streams[0], tlsOutput, false)

				clearTextPacket = NewHandshakePacket([]StreamFrame{*outputFrame}, []AckFrame{*ackFrame}, nil, c)
				defer c.sendHandshakeProtectedPacket(clearTextPacket)
				return false, nil
			}
		case mint.AlertWouldBlock:
			clearTextPacket = NewHandshakePacket(nil, []AckFrame{*ackFrame}, nil, c)
			defer c.sendHandshakeProtectedPacket(clearTextPacket)
			return true, nil
		default:
			return false, alert
		}
	}
}
func (c *Connection) ProcessVersionNegotation(vn *VersionNegotationPacket) error {
	var version uint32
	for _, v := range vn.SupportedVersions {
		if v >= MinimumVersion && v <= MaximumVersion {
			version = uint32(v)
		}
	}
	if version == 0 {
		return errors.New("no appropriate version found")
	}
	QuicVersion, QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
	c.TransitionTo(QuicVersion, QuicALPNToken)
	return nil
}
func (c *Connection) ReadNextPacket() (Packet, error, []byte) {
	rec := make([]byte, MaxUDPPayloadSize, MaxUDPPayloadSize)
	i, _, err := c.UdpConnection.ReadFromUDP(rec)
	if err != nil {
		return nil, err, nil
	}
	rec = rec[:i]

	if c.ReceivedPacketHandler != nil {
		c.ReceivedPacketHandler(rec)
	}

	var headerLen uint8
	var header Header
	if rec[0] & 0x80 == 0x80 {  // Is there a long header ?
		headerLen = LongHeaderSize
		header = ReadLongHeader(bytes.NewReader(rec[:headerLen]))
	} else {
		buf := bytes.NewReader(rec[:LongHeaderSize])
		header = ReadShortHeader(buf, c)  // TODO: Find a better upper bound
		headerLen = uint8(int(buf.Size()) - buf.Len())
	}

	c.receivedPackets++  // TODO: Find appropriate place to increment it

	var packet Packet
	if lHeader, ok := header.(*LongHeader); ok && lHeader.Version == 0x00000000 {
		packet = ReadVersionNegotationPacket(bytes.NewReader(rec))
	} else {
		switch header.PacketType() {
		case Handshake:
			payload, err := c.Cleartext.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[headerLen:], rec[:headerLen])
			if err != nil {
				return nil, err, rec
			}
			buffer := bytes.NewReader(append(rec[:headerLen], payload...))
			packet = ReadHandshakePacket(buffer, c)
		case ZeroRTTProtected, OneBytePacketNumber, TwoBytesPacketNumber, FourBytesPacketNumber:  // Packets with a short header always include a 1-RTT protected payload.
			payload, err := c.protected.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[headerLen:], rec[:headerLen])
			if err != nil {
				return nil, err, rec
			}
			buffer := bytes.NewReader(append(rec[:headerLen], payload...))
			packet = ReadProtectedPacket(buffer, c)
		default:
			spew.Dump(header)
			panic(header.PacketType())
		}

		fullPacketNumber := (c.expectedPacketNumber & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())

		for _, number := range c.ackQueue {
			if number == fullPacketNumber  {
				fmt.Fprintf(os.Stderr, "Received duplicate packet number %d\n", fullPacketNumber)
				spew.Dump(packet)
				return c.ReadNextPacket()
				// TODO: Should it be acked again ?
			}
		}
		c.ackQueue = append(c.ackQueue, fullPacketNumber)
		c.expectedPacketNumber = fullPacketNumber + 1
	}

	return packet, nil, rec
}
func (c *Connection) GetAckFrame() *AckFrame { // Returns an ack frame based on the packet numbers received
	packetNumbers := reverse(c.ackQueue)
	frame := new(AckFrame)
	frame.ackBlocks = make([]AckBlock, 0, 255)
	frame.largestAcknowledged = packetNumbers[0]

	previous := frame.largestAcknowledged
	ackBlock := AckBlock{}
	for _, number := range packetNumbers[1:] {
		if previous - number == 1 {
			ackBlock.block++
		} else {
			frame.ackBlocks = append(frame.ackBlocks, ackBlock)
			ackBlock = AckBlock{previous - number - 1, 0}
		}
		previous = number
	}
	frame.ackBlocks = append(frame.ackBlocks, ackBlock)
	if len(frame.ackBlocks) > 0 {
		frame.ackBlockCount = uint64(len(frame.ackBlocks) - 1)
	}
	return frame
}
func (c *Connection) SendAck(packetNumber uint64) { // Simplistic function that acks packets in sequence only
	protectedPacket := NewProtectedPacket(c)
	protectedPacket.Frames = append(protectedPacket.Frames, NewAckFrame(packetNumber, c.receivedPackets - 1))
	c.SendProtectedPacket(protectedPacket)
}
func (c *Connection) TransitionTo(version uint32, ALPN string) {
	c.tlsBuffer = newConnBuffer()
	tlsConfig := mint.Config{
		ServerName: c.ServerName,
		NonBlocking: true,
		NextProtos: []string{ALPN},
	}
	tlsConfig.Init(true)
	var prevVersion uint32
	if c.Version == 0 {
		prevVersion = QuicVersion
	} else {
		prevVersion = c.Version
	}
	c.TLSTPHandler = NewTLSTransportParameterHandler(version, prevVersion)
	c.Version = version
	tlsConfig.ExtensionHandler = c.TLSTPHandler
	c.tls = mint.Client(c.tlsBuffer, &tlsConfig)
	if c.Version >= 0xff000007 {
		params := mint.CipherSuiteParams {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.3
			Suite:  mint.TLS_AES_128_GCM_SHA256,
			Cipher: nil,
			Hash:   crypto.SHA256,
			KeyLen: 16,
			IvLen:  12,
		}
		c.Cleartext = NewCleartextSaltedCryptoState(c, &params)
	} else {
		c.Cleartext = NewCleartextCryptoState()
	}
	c.Streams = make(map[uint64]*Stream)
	c.Streams[0] = &Stream{}
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint16, reasonPhrase string) {
	pkt := NewProtectedPacket(c)
	if quicLayer {
		pkt.Frames = append(pkt.Frames, ConnectionCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase})
	} else {
		pkt.Frames = append(pkt.Frames, ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase})
	}
	c.SendProtectedPacket(pkt)
}
func (c *Connection) CloseStream(streamId uint64) {
	frame := *NewStreamFrame(streamId, c.Streams[streamId], nil, true)
	if c.protected == nil {
		pkt := NewHandshakePacket(nil, nil, nil, c)
		pkt.StreamFrames = append(pkt.StreamFrames, frame)
		c.sendHandshakeProtectedPacket(pkt)
	} else {
		pkt := NewProtectedPacket(c)
		pkt.Frames = append(pkt.Frames, frame)
		c.SendProtectedPacket(pkt)
	}
}
func NewDefaultConnection(address string, serverName string, useIPv6 bool) (*Connection, error) {
	cId := make([]byte, 8, 8)
	rand.Read(cId)

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
	udpConn, err := net.DialUDP(network, nil, udpAddr)
	if err != nil {
		return nil, err
	}
	udpConn.SetDeadline(time.Now().Add(10*(1e+9)))

	c := NewConnection(serverName, QuicVersion, QuicALPNToken, uint64(binary.BigEndian.Uint64(cId)), udpConn)
	c.useIPv6 = useIPv6
	return c, nil
}

func NewConnection(serverName string, version uint32, ALPN string, connectionId uint64, udpConn *net.UDPConn) *Connection {
	c := new(Connection)
	c.ServerName = serverName
	c.UdpConnection = udpConn
	c.ConnectionId = connectionId
	c.PacketNumber = c.ConnectionId & 0x7fffffff
	c.omitConnectionId = false
	c.receivedPackets = 0

	c.TransitionTo(version, ALPN)

	return c
}

func assert(value bool) {
	if !value {
		panic("")
	}
}