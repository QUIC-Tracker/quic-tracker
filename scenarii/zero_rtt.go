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
package scenarii

import (
	m "github.com/mpiraux/master-thesis"
	"time"
	"net"
	"fmt"
)

const (
	ZR_TLSHandshakeFailed           = 1
	ZR_NoResumptionSecret           = 2
	ZR_ZeroRTTFailed                = 3
	ZR_DidntReceiveTheRequestedData = 4
)

type ZeroRTTScenario struct {
	AbstractScenario
}

func NewZeroRTTScenario() *ZeroRTTScenario {
	return &ZeroRTTScenario{AbstractScenario{"zero_rtt", 1, false}}
}
func (s *ZeroRTTScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	_, err := CompleteHandshake(conn)
	if err != nil {
		trace.MarkError(ZR_TLSHandshakeFailed, err.Error())
		return
	}

	conn.UdpConnection.SetDeadline(time.Now().Add(3 * time.Second))
	conn.CloseConnection(false, 0, "")
	conn.RetransmissionTicker.Stop()

	for { // Acks and restransmits if needed
		packet, err, _ := conn.ReadNextPackets()

		if nerr, ok := err.(*net.OpError); ok && nerr.Timeout() {
			break
		} else if err != nil {
			trace.Results["error"] = err.Error()
		}
		for _, packet := range packet {
			if packet.ShouldBeAcknowledged() {
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(protectedPacket)
			}
		}
	}

	resumptionSecret := conn.Tls.GetResumptionTicket()

	if len(resumptionSecret) == 0 {
		trace.ErrorCode = ZR_NoResumptionSecret
		return
	}

	conn.Close()
	rh, sh := conn.ReceivedPacketHandler, conn.SentPacketHandler
	conn, err = m.NewDefaultConnection(conn.Host.String(), conn.ServerName, resumptionSecret, s.ipv6)
	conn.ReceivedPacketHandler = rh
	conn.SentPacketHandler = sh
	if err != nil {
		trace.ErrorCode = ZR_ZeroRTTFailed
		trace.Results["error"] = err.Error()
		return
	}
	conn.RetransmissionTicker.Stop() // Stop retransmissions until fixed for 0-RTT

	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
	conn.ZeroRTTprotected = m.NewZeroRTTProtectedCryptoState(conn.Tls)

	pp := m.NewZeroRTTProtectedPacket(conn)
	conn.Streams[4] = new(m.Stream)
	pp.Frames = append(pp.Frames, m.NewStreamFrame(4, conn.Streams[4], []byte(fmt.Sprintf("GET %s\r\n", preferredUrl)), true))
	conn.SendZeroRTTProtectedPacket(pp)

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPackets()
		if err != nil {
			break
		}

		for _, packet := range packet {
			if scp, ok := packet.(*m.HandshakePacket); ok {
				ongoingHandhake, packet, err = conn.ProcessServerHello(scp)
				if err != nil {
					trace.MarkError(ZR_ZeroRTTFailed, err.Error())
					break
				}
				conn.SendHandshakeProtectedPacket(packet)
			} else {
				trace.MarkError(ZR_ZeroRTTFailed, "Received unexpected packet type during handshake")
				break
			}
		}
	}


	streamClosed := false
	for !streamClosed {
		packets, err, _ := conn.ReadNextPackets()

		if err != nil {
			trace.Results["error"] = err.Error()
			break
		}

		for _, packet := range packets {
			if packet.ShouldBeAcknowledged() {
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(protectedPacket)
			}

			for streamId, stream := range conn.Streams {
				if streamId == 4 && stream.ReadClosed {
					streamClosed = true
					break
				}
			}

			if streamClosed {
				conn.CloseConnection(false, 0, "")
				break
			}
		}
	}

	if !streamClosed {
		trace.ErrorCode = ZR_DidntReceiveTheRequestedData
	}

}
