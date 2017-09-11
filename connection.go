package main

import (
	"github.com/bifurcation/mint"
	"crypto/rand"
	"encoding/binary"
	"net"
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"time"
)

type Connection struct {
	udpConnection 	 *net.UDPConn
	tlsBuffer	  	 *connBuffer
	tls     	  	 *mint.Conn

	cleartext        *CryptoState
	protected        *CryptoState
	cipherSuite		 *mint.CipherSuiteParams

	streams			 map[uint32]*Stream
	connectionId  	 uint64
	packetNumber  	 uint64
	version       	 uint32
	omitConnectionId bool
	ackQueue		 []uint64  // Stores the packet numbers to be acked
	receivedPackets  uint64  // TODO: Implement proper ACK mechanism
}
func (c *Connection) nextPacketNumber() uint64 {
	c.packetNumber++
	return c.packetNumber
}
func (c *Connection) sendAEADSealedPacket(header []byte, payload []byte, packetNumber uint32) {
	protectedPayload := c.cleartext.write.Seal(nil, encodeArgs(packetNumber), payload, header)
	finalPacket := make([]byte, 0, 1500)  // TODO Find a proper upper bound on total packet size
	finalPacket = append(finalPacket, header...)
	finalPacket = append(finalPacket, protectedPayload...)
	c.udpConnection.Write(finalPacket)
}
func (c *Connection) sendProtectedPacket(header []byte, payload []byte, packetNumber uint32) {
	protectedPayload := c.protected.write.Seal(nil, encodeArgs(packetNumber), payload, header)
	finalPacket := make([]byte, 0, 1500)  // TODO Find a proper upper bound on total packet size
	finalPacket = append(finalPacket, header...)
	finalPacket = append(finalPacket, protectedPayload...)
	c.udpConnection.Write(finalPacket)
}
func (c *Connection) sendClientInitialPacket() {
	c.tls.Handshake()
	handshakeResult := c.tlsBuffer.getOutput()
	handshakeFrame := NewStreamFrame(0, c.streams[0], handshakeResult, false)

	clientInitialPacket := NewClientInitialPacket(make([]StreamFrame, 0, 1), make([]PaddingFrame, 0, MinimumClientInitialLength), c)
	clientInitialPacket.streamFrames = append(clientInitialPacket.streamFrames, *handshakeFrame)
	paddingLength := MinimumClientInitialLength - (LongHeaderSize + len(clientInitialPacket.encodePayload()) + c.protected.write.Overhead())
	for i := 0; i < paddingLength; i++ {
		clientInitialPacket.padding = append(clientInitialPacket.padding, *new(PaddingFrame))
	}

	c.sendAEADSealedPacket(clientInitialPacket.encodeHeader(), clientInitialPacket.encodePayload(), clientInitialPacket.header.PacketNumber())
}
func (c *Connection) processServerHello(packet *ServerCleartextPacket) bool { // Returns whether or not the TLS Handshake should continue
	c.connectionId = packet.header.ConnectionId()  // see https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.6

	var serverData []byte
	for _, frame := range packet.streamFrames {
		serverData = append(serverData, frame.streamData...)
	}

	var clearTextPacket *ClientCleartextPacket
	ackFrame := NewAckFrame(uint64(packet.header.PacketNumber()), c.receivedPackets - 1)

	c.tlsBuffer.input(serverData)
	alert := c.tls.Handshake()
	switch alert {
	case mint.AlertNoAlert:
		tlsOutput := c.tlsBuffer.getOutput()

		state := c.tls.State()
		// TODO: Check negotiated ALPN ?
		c.cipherSuite = &state.CipherSuite
		c.protected = NewProtectedCryptoState(c)

		outputFrame := NewStreamFrame(0, c.streams[0], tlsOutput, false)

		clearTextPacket = NewClientCleartextPacket([]StreamFrame{*outputFrame}, []AckFrame{*ackFrame}, nil, c)
		defer c.sendAEADSealedPacket(clearTextPacket.encodeHeader(), clearTextPacket.encodePayload(), clearTextPacket.header.PacketNumber())
		return false
	case mint.AlertWouldBlock:
		clearTextPacket = NewClientCleartextPacket(nil, []AckFrame{*ackFrame}, nil, c)
		defer c.sendAEADSealedPacket(clearTextPacket.encodeHeader(), clearTextPacket.encodePayload(), clearTextPacket.header.PacketNumber())
		return true
	default:
		panic(alert)
	}
}
func (c *Connection) readNextPacket() Packet {
	rec := make([]byte, MaxUDPPayloadSize, MaxUDPPayloadSize)
	i, _, err := c.udpConnection.ReadFromUDP(rec)
	if err != nil {
		panic(err)
	}
	rec = rec[:i]

	var headerLen uint8
	if rec[0] & 0x80 == 0x80 {  // Is there a long header ?
		headerLen = LongHeaderSize
	} else {
		panic("TODO readNextPacket w/ short header")
	}

	c.receivedPackets++
	header := ReadLongHeader(bytes.NewReader(rec[:headerLen]))
	switch header.packetType {
	case ServerCleartext:
		payload, err := c.cleartext.read.Open(nil, encodeArgs(header.packetNumber), rec[headerLen:], rec[:headerLen])
		if err != nil {
			panic(err)
		}
		buffer := bytes.NewReader(append(rec[:headerLen], payload...))
		return ReadServerCleartextPacket(buffer, c)
	case OneRTTProtectedKP0:
		payload, err := c.protected.read.Open(nil, encodeArgs(header.packetNumber), rec[headerLen:], rec[:headerLen])
		if err != nil {
			panic(err)
		}
		buffer := bytes.NewReader(append(rec[:headerLen], payload...))
		return ReadProtectedPacket(buffer, c)
	default:
		panic(header.packetType)
	}
}
func (c *Connection) getAckFrame() *AckFrame {  // Returns an ack frame based on the packet number received
	packetNumbers := reverse(c.ackQueue)
	frame := new(AckFrame)
	frame.ackBlocks = make([]AckBlock, 0, 255)
	frame.largestAcknowledged = packetNumbers[0]

	previous := frame.largestAcknowledged
	ackBlock := AckBlock{}
	for _, number := range packetNumbers[1:] {
		if number - previous == 1 {
			ackBlock.ack++
		} else {
			frame.ackBlocks = append(frame.ackBlocks, ackBlock)
			ackBlock = AckBlock{uint8(number - previous - 1), 0}  // TODO: Handle gaps larger than 255 packets
		}
	}
	frame.ackBlocks = append(frame.ackBlocks, ackBlock)
	frame.numBlocksPresent = len(frame.ackBlocks) > 1
	frame.numAckBlocks = uint8(len(frame.ackBlocks)-1)
	return frame
}
func (c *Connection) sendAck(packetNumber uint64) { // Simplistic function that acks packets in sequence only
	protectedPacket := NewProtectedPacket(c)
	protectedPacket.frames = append(protectedPacket.frames, NewAckFrame(packetNumber, c.receivedPackets - 1))
	c.sendProtectedPacket(protectedPacket.encodeHeader(), protectedPacket.encodePayload(), protectedPacket.header.PacketNumber())
}

func NewConnection(address string, serverName string) *Connection {
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		panic(err)
	}
	udpConn, err := net.DialUDP("udp4", nil, udpAddr)
	if err != nil {
		panic(err)
	}
	udpConn.SetDeadline(time.Time{})

	c := new(Connection)
	c.udpConnection = udpConn
	c.tlsBuffer = newConnBuffer()
	tlsConfig := mint.Config{
		ServerName: serverName,
		NonBlocking: true,
		NextProtos: []string{QuicALPNToken},
	}
	tlsConfig.Init(true)
	c.tls = mint.Client(c.tlsBuffer, &tlsConfig)
	c.cleartext = NewCleartextCryptoState()
	cId := make([]byte, 8, 8)
	rand.Read(cId)
	c.connectionId = uint64(binary.BigEndian.Uint64(cId))
	c.packetNumber = c.connectionId & 0x7fffffff
	c.version = QuicVersion
	c.omitConnectionId = false

	c.streams = make(map[uint32]*Stream)
	c.streams[0] = &Stream{}

	return c
}

func assert(value bool) {
	if !value {
		panic("")
	}
}

func main() {
	//conn := NewConnection("quant.eggert.org:4433", "quant.eggert.org")
	//conn := NewConnection("kotdt.com:4433", "kotdt.com")
	conn := NewConnection("localhost:4433", "localhost")
	conn.sendClientInitialPacket()
	var packet Packet

	ongoingHandhake := true
	for ongoingHandhake {
		packet = conn.readNextPacket()
		if packet, ok := packet.(*ServerCleartextPacket); ok {
			ongoingHandhake = conn.processServerHello(packet)
		} else {
			spew.Dump(packet)
			panic(packet)
		}
	}

	conn.streams[1] = &Stream{}
	streamFrame := NewStreamFrame(1, conn.streams[1], []byte("GET /index.html HTTP/1.0\nHost: localhost\n\n"), false)
	ackFrame := NewAckFrame(uint64(packet.Header().PacketNumber()), conn.receivedPackets - 1)

	protectedPacket := NewProtectedPacket(conn)
	protectedPacket.frames = append(protectedPacket.frames, streamFrame, ackFrame)
	conn.sendProtectedPacket(protectedPacket.encodeHeader(), protectedPacket.encodePayload(), protectedPacket.header.PacketNumber())

	for {
		var ok bool
		packet = conn.readNextPacket()
		conn.sendAck(uint64(packet.Header().PacketNumber()))
		packet, ok = packet.(*ProtectedPacket)
		if ok {
			spew.Dump(packet)
		}
	}

}