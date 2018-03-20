/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package main

import (
	"github.com/davecgh/go-spew/spew"
	m "github.com/mpiraux/master-thesis"
	"flag"
	"strings"
)

func main() {
	address := flag.String("address", "", "The address to connect to")
	useIPv6 := flag.Bool("6", false, "Use IPV6")
	flag.Parse()
	conn, err := m.NewDefaultConnection(*address, (*address)[:strings.LastIndex(*address, ":")], *useIPv6)
	if err != nil {
		panic(err)
	}
	pcap, err := m.StartPcapCapture(conn)
	if err != nil {
		panic(err)
	}
	defer func() {spew.Dump(m.StopPcapCapture(pcap))}()
	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			spew.Dump(err)
			return
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, err = conn.ProcessServerHello(scp)
			if err != nil {
				spew.Dump(err)
				return
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err == nil {
				conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
			} else {
				println("No version in common with " + *address)
				spew.Dump(vn)
				return
			}
		} else {
			spew.Dump(packet)
			return
		}
	}

	conn.Streams[4] = &m.Stream{}
	streamFrame := m.NewStreamFrame(4, conn.Streams[4], []byte("GET /index.html\r\n"), false)
	ackFrame := conn.GetAckFrame()

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame, ackFrame)
	conn.SendProtectedPacket(protectedPacket)

	for {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			spew.Dump(err)
			break
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