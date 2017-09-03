package main

import (
	"github.com/bifurcation/mint"
	"net"
	"math/rand"
	"time"
	"crypto/cipher"
)

type Connection struct {
	udpConnection 	 *net.Conn
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

	hdr := clientInitialPacket.encodeHeader()
	payload := clientInitialPacket.encodePayload()

	protectedPayload := c.aead.Seal(nil, encodeArgs(clientInitialPacket.header.PacketNumber()), payload, hdr)
	finalPacket := make([]byte, 0, 1500)
	finalPacket = append(finalPacket, hdr...)
	finalPacket = append(finalPacket, protectedPayload...)
	(*c.udpConnection).Write(finalPacket)
}
func NewConnection(address string, serverName string) *Connection {
	udpConn, err := net.Dial("udp", address)
	if err != nil {
		panic(err)
	}
	udpConn.SetDeadline(time.Time{})

	c := new(Connection)
	c.udpConnection = &udpConn
	c.tlsBuffer = newConnBuffer()
	tlsConfig := mint.Config{
		ServerName: serverName,
		NonBlocking: true,
		NextProtos: []string{QuicALPNToken},
	}
	tlsConfig.Init(true)
	c.tls = mint.Client(c.tlsBuffer, &tlsConfig)
	c.aead = &aeadFNV{}
	c.connectionId = uint64(rand.Uint32()) << 32 + uint64(rand.Uint32())
	c.packetNumber = c.connectionId & 0x7fffffff
	c.version = QuicVersion
	c.omitConnectionId = false

	return c
}

func main() {
	conn := NewConnection("quant.eggert.org:4433", "quant.eggert.org")
	conn.sendClientInitialPacket()
}