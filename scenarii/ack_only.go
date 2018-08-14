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
	qt "github.com/QUIC-Tracker/quic-tracker"

	"time"
)

const (
	AO_TLSHandshakeFailed   = 1
	AO_SentAOInResponseOfAO = 2
)

type AckOnlyScenario struct {
	AbstractScenario
}

func NewAckOnlyScenario() *AckOnlyScenario {
	return &AckOnlyScenario{AbstractScenario{"ack_only", 1, false, nil}}
}
func (s *AckOnlyScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := s.CompleteHandshake(conn, trace, AO_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")
	connAgents.Get("AckAgent").Stop()
	connAgents.Get("AckAgent").Join()

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	conn.SendHTTPGETRequest(preferredUrl, 0)

	var ackOnlyPackets []uint64

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if p.PNSpace() != qt.PNSpaceAppData {
				break
			}
			if p.ShouldBeAcknowledged() {
				ackFrame := conn.GetAckFrame(qt.PNSpaceAppData)
				if ackFrame == nil {
					break
				}
				protectedPacket := qt.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(qt.PNSpaceAppData))
				conn.SendPacket(protectedPacket, qt.EncryptionLevel1RTT)
				ackOnlyPackets = append(ackOnlyPackets, uint64(protectedPacket.Header().PacketNumber()))
			} else if framer, ok := p.(qt.Framer); ok && framer.Contains(qt.AckType) {
				ack := framer.GetFirst(qt.AckType).(*qt.AckFrame)
				if containsAll(ack.GetAckedPackets(), ackOnlyPackets) {
					trace.MarkError(AO_SentAOInResponseOfAO, "", p)
					return
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}

func containsAll(a []uint64, b []uint64) bool { // Checks a \in b
	for _, i := range a {
		contains := false
		for _, j := range b {
			if i == j {
				contains = true
				break
			}
		}
		if !contains {
			return false
		}
	}
	return true
}
