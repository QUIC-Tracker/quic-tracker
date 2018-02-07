package main

import (
	"github.com/davecgh/go-spew/spew"
	m "masterthesis"
)

func main() {
	conn := m.NewDefaultConnection("quant.eggert.org:4433", "quant.eggert.org")
	//conn := m.NewDefaultConnection("kotdt.com:4433", "kotdt.com")
	//conn := m.NewDefaultConnection("localhost:4433", "localhost")
	//conn := m.NewDefaultConnection("minq.dev.mozaws.net:4433", "minq.dev.mozaws.net")
	//conn := m.NewDefaultConnection("mozquic.ducksong.com:4433", "mozquic.ducksong.com")
	//conn := m.NewDefaultConnection("quic.ogre.com:4433", "quic.ogre.com")
	//conn := m.NewDefaultConnection("kazuhooku.com:4433", "kazuhooku.com")
	//conn := m.NewDefaultConnection("fb.mvfst.net:4433", "fb.mvfst.net")
	conn.SendInitialPacket()

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			panic(err)
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, err = conn.ProcessServerHello(scp)
			if err != nil {
				panic(err)
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			conn.ProcessVersionNegotation(vn)
			conn.SendInitialPacket()
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
		packet, err, _ := conn.ReadNextPacket()
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