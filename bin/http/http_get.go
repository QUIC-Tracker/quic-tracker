package main

import (
	"github.com/davecgh/go-spew/spew"
	m "masterthesis"
	"flag"
)

func main() {
	address := flag.String("address", "", "The address to connect to")
	useIPv6 := flag.Bool("6", false, "Use IPV6")
	flag.Parse()
	conn, err := m.NewDefaultConnection(*address, "test.privateoctopus.com", *useIPv6)
	if err != nil {
		panic(err)
	}
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

	conn.Streams[4] = &m.Stream{}
	streamFrame := m.NewStreamFrame(4, conn.Streams[4], []byte("GET /index.html HTTP/1.0\nHost: localhost\n\n"), false)
	ackFrame := conn.GetAckFrame()

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame, ackFrame)
	conn.SendProtectedPacket(protectedPacket)

	for {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			panic(err)
		}

		spew.Dump("---> Received packet")
		spew.Dump(packet)

		if packet.ShouldBeAcknowledged() {
			protectedPacket = m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			spew.Dump("<--- Send ack packet")
			spew.Dump(protectedPacket)
			conn.SendProtectedPacket(protectedPacket)
		}
	}

}