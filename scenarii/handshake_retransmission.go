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
)

const (
	HR_DidNotRetransmitHandshake = 1
	HR_VNDidNotComplete          = 2
	HR_TLSHandshakeFailed        = 3
	HR_NoPathChallengeReceived   = 4
)

type HandshakeRetransmissionScenario struct {
	AbstractScenario
}
func NewHandshakeRetransmissionScenario() *HandshakeRetransmissionScenario {
	return &HandshakeRetransmissionScenario{AbstractScenario{"handshake_retransmission", 2, false}}
}
func (s *HandshakeRetransmissionScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	initial := conn.GetInitialPacket()
	conn.SendHandshakeProtectedPacket(initial)

	var arrivals []uint64
	totalDataReceived := 0

	var start time.Time
	ongoingHandshake := true
	receivedPathChallenge := false
	handshakePacketReceived := 0
	handshakePacketReceivedBeforePC := 0

outerLoop:
	for {
		packets, err, rec := conn.ReadNextPackets()

		if err != nil {
			break
		}

		totalDataReceived += len(rec)

		for _, packet := range packets {
			if handshake, ok := packet.(*m.HandshakePacket); ok {
				var isRetransmit bool
				for _, frame := range handshake.Frames { // TODO Distinguish retransmits-only packets from packets bundling retransmitted and new frames ?
					if streamFrame, ok := frame.(*m.StreamFrame); ok && streamFrame.StreamId == 0 && streamFrame.Offset == 0 {
						isRetransmit = true
						break
					}
				}

				if isRetransmit {
					if start.IsZero() {
						start = time.Now()
					}
					arrivals = append(arrivals, uint64(time.Now().Sub(start).Seconds()*1000))
				}

				if ongoingHandshake {
					ongoingHandshake, packet, err = conn.ProcessServerHello(handshake)
					if err != nil {
						trace.MarkError(HR_TLSHandshakeFailed, err.Error())
						break outerLoop
					}
				}

				handshakePacketReceived++
				if !receivedPathChallenge {
					handshakePacketReceivedBeforePC++
				}

				if handshake.Contains(m.PathChallengeType) {
					receivedPathChallenge = true
				}
			} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
				if err := conn.ProcessVersionNegotation(vn); err != nil {
					trace.MarkError(HR_VNDidNotComplete, err.Error())
					break outerLoop
				}
				initial = conn.GetInitialPacket()
				conn.SendHandshakeProtectedPacket(initial)
				totalDataReceived = 0
			} else {
				continue
			}
		}
	}

	if len(arrivals) == 1 {
		trace.ErrorCode = HR_DidNotRetransmitHandshake
	}
	if handshakePacketReceived > 3 && !receivedPathChallenge {
		trace.ErrorCode = HR_NoPathChallengeReceived
	}

	trace.Results["arrival_times"] = arrivals
	trace.Results["total_data_received"] = totalDataReceived
	trace.Results["amplification_factor"] = float64(totalDataReceived) / float64(len(initial.Encode(initial.EncodePayload())))
}
