package main

import (
	"github.com/bifurcation/mint"
	"net"
	"math/rand"
	"bytes"
	"time"
)

func main() {
	udpConn, err := net.Dial("udp", "quant.eggert.org:4433")
	if err != nil {
		panic(err)
	}
	udpConn.SetDeadline(time.Time{})

	tlsBuf := newConnBuffer()
	config := mint.Config{
		ServerName:"quant.eggert.org",
		NonBlocking: true,
		NextProtos: []string{QuicALPNToken},
	}
	config.Init(true)
	client := mint.Client(tlsBuf, &config)
	connId := uint64(rand.Uint32())<<32 + uint64(rand.Uint32())
	aead := &aeadFNV{}

	client.Handshake()
	handshakeResult := tlsBuf.getOutput()
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
	longHeader := LongHeader{
		ClientInitial,
		connId,
		uint32(connId & 0x7fffffff),
		QuicVersion,
	}
	clientInitialPacket := ClientInitialPacket{}
	clientInitialPacket.header = &longHeader
	clientInitialPacket.streamFrames = append(clientInitialPacket.streamFrames, handshakeFrame)
	paddingLength := MinimumClientInitialLength - (LongHeaderSize + 23 + len(handshakeResult))
	for i := 0; i < paddingLength; i++ {
		clientInitialPacket.padding = append(clientInitialPacket.padding, *new(PaddingFrame))
	}
	buffer := new(bytes.Buffer)
	clientInitialPacket.writeTo(buffer)

	packetLen := buffer.Len()
	hdr := buffer.Next(17)
	payload := buffer.Next(packetLen - 17)

	protectedPayload := aead.Seal(nil, encodeArgs(clientInitialPacket.header.packetNumber), payload, hdr)
	finalPacket := make([]byte, 0, 1500)
	finalPacket = append(finalPacket, hdr...)
	finalPacket = append(finalPacket, protectedPayload...)

	udpConn.Write(finalPacket)
}