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
	"errors"
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
	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(ZR_TLSHandshakeFailed, err.Error(), p)
		return
	}

	conn.UdpConnection.SetDeadline(time.Now().Add(3 * time.Second))

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
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(packet.PNSpace()))
				conn.SendProtectedPacket(protectedPacket)
			}

			select {
			case resumptionData := <- conn.Streams.Get(0).ReadChan:
				tlsOutput, _, err := conn.Tls.Input(resumptionData)
				if err != nil {
					trace.MarkError(ZR_TLSHandshakeFailed, err.Error(), packet)
					return
				}

				if len(tlsOutput) > 0 {
					protectedPacket := m.NewProtectedPacket(conn)
					protectedPacket.Frames = append(protectedPacket.Frames, m.NewStreamFrame(0, conn.Streams.Get(0), tlsOutput, false))
					conn.SendProtectedPacket(protectedPacket)
				}
			default:

			}
		}

		if len(conn.Tls.ResumptionTicket()) > 0 {
			conn.CloseConnection(false, 0, "")
			conn.RetransmissionTicker.Stop()
		}
	}

	resumptionSecret := conn.Tls.ResumptionTicket()

	if len(resumptionSecret) == 0 {
		trace.ErrorCode = ZR_NoResumptionSecret
		return
	}

	conn.Close()
	rh, sh := conn.ReceivedPacketHandler, conn.SentPacketHandler
	conn, err := m.NewDefaultConnection(conn.Host.String(), conn.ServerName, resumptionSecret, s.ipv6)
	conn.ReceivedPacketHandler = rh
	conn.SentPacketHandler = sh
	if err != nil {
		trace.ErrorCode = ZR_ZeroRTTFailed
		trace.Results["error"] = err.Error()
		return
	}
	conn.RetransmissionTicker.Stop() // Stop retransmissions until fixed for 0-RTT

	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	if conn.Tls.ZeroRTTSecret() != nil {
		conn.ZeroRTTCrypto = m.NewProtectedCryptoState(conn.Tls, nil, conn.Tls.ZeroRTTSecret())
	} else {
		trace.ErrorCode = ZR_ZeroRTTFailed
		trace.Results["error"] = errors.New("no zero rtt secret available")
	}

	pp := m.NewZeroRTTProtectedPacket(conn)
	pp.Frames = append(pp.Frames, m.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", preferredUrl)), true))
	conn.SendZeroRTTProtectedPacket(pp)

	ongoingHandhake := true
	wasStateless := false
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPackets()
		if err != nil {
			break
		}

		for _, packet := range packet {
			if fp, ok := packet.(m.Framer); ok {
				var response m.Packet
				ongoingHandhake, response, err = conn.ProcessServerHello(fp)
				if err != nil {
					trace.MarkError(ZR_ZeroRTTFailed, err.Error(), response)
					break
				}
				conn.SendHandshakeProtectedPacket(packet)
			} else if _, ok := packet.(*m.RetryPacket); ok {
				wasStateless = true
			} else {
				trace.MarkError(ZR_ZeroRTTFailed, "Received unexpected packet type during handshake", packet)
				break
			}
		}
	}

	if wasStateless {
		pp2 := m.NewProtectedPacket(conn)
		pp2.Frames = pp.Frames
		conn.SendProtectedPacket(pp2)
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
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(packet.PNSpace()))
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
