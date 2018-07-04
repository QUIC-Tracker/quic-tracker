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
)

const (
	AO_TLSHandshakeFailed   = 1
	AO_SentAOInResponseOfAO = 2
)

type AckOnlyScenario struct {
	AbstractScenario
}

func NewAckOnlyScenario() *AckOnlyScenario {
	return &AckOnlyScenario{AbstractScenario{"ack_only", 1, false}}
}
func (s *AckOnlyScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(AO_TLSHandshakeFailed, err.Error(), p)
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 4)

	var ackOnlyPackets []uint64

	for p := range conn.IncomingPackets {
		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
			ackOnlyPackets = append(ackOnlyPackets, uint64(protectedPacket.Header().PacketNumber()))
		}

		if framer, ok := p.(m.Framer); ok && !p.ShouldBeAcknowledged() && framer.Contains(m.AckType){
			ack := framer.GetFirst(m.AckType).(*m.AckFrame)
			if containsAll(ack.GetAckedPackets(), ackOnlyPackets) {
				trace.MarkError(AO_SentAOInResponseOfAO, "", p)
				break
			}
		}
	}
	conn.CloseConnection(false, 0, "")
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
