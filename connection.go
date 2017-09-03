package main

import (
	"github.com/bifurcation/mint"
	"crypto/rand"
	"crypto/cipher"
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
	aead             cipher.AEAD
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
	protectedPayload := c.aead.Seal(nil, encodeArgs(packetNumber), payload, header)
	finalPacket := make([]byte, 0, 1500)  // TODO Find a proper upper bound on total packet size
	finalPacket = append(finalPacket, header...)
	finalPacket = append(finalPacket, protectedPayload...)
	c.udpConnection.Write(finalPacket)
}
func (c *Connection) sendClientInitialPacket() {
	c.tls.Handshake()
	handshakeResult := c.tlsBuffer.getOutput()
	handshakeFrame := StreamFrame{
		false,
		3,
		3,
		true,
		0,
		0,
		uint16(len(handshakeResult)),
		handshakeResult,
	}

	clientInitialPacket := NewClientInitialPacket(make([]StreamFrame, 0, 1), make([]PaddingFrame, 0, MinimumClientInitialLength), c)
	clientInitialPacket.streamFrames = append(clientInitialPacket.streamFrames, handshakeFrame)
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
	_ = c.tlsBuffer.getOutput()

	// TODO: Prepare new crypto state
	// TODO: Send tls output on stream 0
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
		payload, err := c.aead.Open(nil, encodeArgs(header.packetNumber), rec[headerLen:], rec[:headerLen])
		if err != nil {
			panic(err)
		}
		buffer := bytes.NewReader(append(rec[:headerLen], payload...))
		return ReadServerCleartextPacket(buffer)
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
	c.aead = &aeadFNV{}
	cId := make([]byte, 8, 8)
	rand.Read(cId)
	c.connectionId = uint64(binary.BigEndian.Uint64(cId))
	c.packetNumber = c.connectionId & 0x7fffffff
	c.version = QuicVersion
	c.omitConnectionId = false

	return c
}

func main() {
	conn := NewConnection("quant.eggert.org:4433", "quant.eggert.org")
	conn.sendClientInitialPacket()
	packet := conn.readNextPacket()
	if packet, ok := packet.(*ServerCleartextPacket); ok {
		conn.completeServerHello(packet)
	} else {
		//spew.Dump(packet)
		panic(packet)
	}

}