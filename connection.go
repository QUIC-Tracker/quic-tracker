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
	paddingLength := MinimumClientInitialLength - (LongHeaderSize + len(clientInitialPacket.encodePayload()) + 8)
	for i := 0; i < paddingLength; i++ {
		clientInitialPacket.padding = append(clientInitialPacket.padding, *new(PaddingFrame))
	}

	c.sendAEADSealedPacket(clientInitialPacket.encodeHeader(), clientInitialPacket.encodePayload(), clientInitialPacket.header.PacketNumber())
}
func (c *Connection) completeServerHello(packet *ServerCleartextPacket) {
	var serverData []byte
	for _, frame := range packet.streamFrames {
		serverData = append(serverData, frame.streamData...)
	}

	c.tlsBuffer.input(serverData)
	c.tls.Handshake()
	tlsOutput := c.tlsBuffer.getOutput()

	state := c.tls.State()
	// TODO: Check negotiated ALPN ?
	c.cipherSuite = &state.CipherSuite
	spew.Dump(c.cipherSuite)
	c.protected = NewProtectedCryptoState(c)

	outputFrame := NewStreamFrame(0, c.streams[0], tlsOutput, false)
	clearTestPacket := NewClientCleartextPacket([]StreamFrame{*outputFrame}, nil, nil, c)
	c.sendAEADSealedPacket(clearTestPacket.encodeHeader(), clearTestPacket.encodePayload(), clearTestPacket.header.PacketNumber())
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

	header := ReadLongHeader(bytes.NewReader(rec[:headerLen]))
	if header.packetType == ServerCleartext {
		payload, err := c.cleartext.read.Open(nil, encodeArgs(header.packetNumber), rec[headerLen:], rec[:headerLen])
		if err != nil {
			panic(err)
		}
		buffer := bytes.NewReader(append(rec[:headerLen], payload...))
		return ReadServerCleartextPacket(buffer, c)
	} else {
		panic(header.packetType)
	}
	return nil
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
	conn := NewConnection("kotdt.com:4433", "kotdt.com")
	//conn := NewConnection("localhost:4433", "quant.eggert.org")
	conn.sendClientInitialPacket()
	packet := conn.readNextPacket()
	if packet, ok := packet.(*ServerCleartextPacket); ok {
		conn.completeServerHello(packet)
	} else {
		spew.Dump(packet)
		panic(packet)
	}

	packet = conn.readNextPacket()
	if packet, ok := packet.(*ServerCleartextPacket); ok {
		assert(len(packet.streamFrames) == 0)
		assert(len(packet.ackFrames) == 1)
	} else {
		spew.Dump(packet)
		panic(packet)
	}
	conn.streams[1] = &Stream{}
	streamFrame := NewStreamFrame(1, conn.streams[1], []byte("Hello, world!\n"), false)
	protectedPacket := NewProtectedPacket(conn)
	protectedPacket.frames = append(protectedPacket.frames, streamFrame)
	conn.sendProtectedPacket(protectedPacket.encodeHeader(), protectedPacket.encodePayload(), protectedPacket.header.PacketNumber())

	packet = conn.readNextPacket()
	if packet, ok := packet.(*ProtectedPacket); ok {
		spew.Dump(packet)
	} else {
		spew.Dump(packet)
		panic(packet)
	}
}