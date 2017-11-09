package main

import (
	"github.com/davecgh/go-spew/spew"
	m "masterthesis"
)

func main() {
	//conn := NewConnection("quant.eggert.org:4433", "quant.eggert.org")
	//conn := NewConnection("kotdt.com:4433", "kotdt.com")
	//conn := NewConnection("localhost:4433", "localhost")
	//conn := NewConnection("minq.dev.mozaws.net:4433", "minq.dev.mozaws.net")
	conn := m.NewConnection("mozquic.ducksong.com:4433", "mozquic.ducksong.com")
	conn.SendClientInitialPacket()

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err := conn.ReadNextPacket()
		if err != nil {
			panic(err)
		}
		if packet, ok := packet.(*m.ServerCleartextPacket); ok {
			ongoingHandhake = conn.ProcessServerHello(packet)
		} else {
			spew.Dump(packet)
			panic(packet)
		}
	}

	conn.Streams[1] = &m.Stream{}
	streamFrame := m.NewStreamFrame(1, conn.Streams[1], []byte("GET /index.html HTTP/1.0\nHost: localhost\n\n"), false)
	ackFrame := conn.GetAckFrame()

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame, ackFrame)
	conn.SendProtectedPacket(protectedPacket)

	for {
		packet, err := conn.ReadNextPacket()
		if err != nil {
			panic(err)
		}
		conn.SendAck(uint64(packet.Header().PacketNumber()))

		spew.Dump("---> Received packet")
		//spew.Dump(packet)

		if packet.ShouldBeAcknowledged() {
			protectedPacket = m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			spew.Dump("<--- Send ack packet")
			//spew.Dump(protectedPacket)
			conn.SendProtectedPacket(protectedPacket)
		}
	}

}