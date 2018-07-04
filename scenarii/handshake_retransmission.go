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
	HR_DidNotRetransmitHandshake   = 1
	HR_VNDidNotComplete            = 2
	HR_TLSHandshakeFailed          = 3
	HR_NoPathChallengeReceived     = 4
	HR_NoPathChallengeInAllPackets = 5
	HR_NoPathChallengeConfirmation = 6
)

type HandshakeRetransmissionScenario struct {
	AbstractScenario
}
func NewHandshakeRetransmissionScenario() *HandshakeRetransmissionScenario {
	return &HandshakeRetransmissionScenario{AbstractScenario{"handshake_retransmission", 2, false}}
}
func (s *HandshakeRetransmissionScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	initial := conn.GetInitialPacket()
	conn.IgnorePathChallenge = true
	conn.DisableIncPacketChan = true  // TODO: Integrate this scenario
	conn.SendHandshakeProtectedPacket(initial)

	var arrivals []uint64
	totalDataReceived := 0

	var start time.Time
	ongoingHandshake := true
	isStateless := false
	pathChallengeReceived := 0
	handshakePacketReceived := 0
	handshakePacketReceivedBeforePC := 0
	var packetFinished m.Packet = nil

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
					var response m.Packet
					ongoingHandshake, response, err = conn.ProcessServerHello(handshake)
					if err != nil {
						trace.MarkError(HR_TLSHandshakeFailed, err.Error(), response)
						break outerLoop
					}
					if !ongoingHandshake {
						packetFinished = packet
					}
				}

				handshakePacketReceived++

				if handshake.Contains(m.PathChallengeType) {
					pathChallengeReceived++
					if pathChallenge := handshake.GetFirst(m.PathChallengeType); trace.ErrorCode != HR_NoPathChallengeConfirmation && !ongoingHandshake && (handshakePacketReceived < 3 || handshakePacketReceived == pathChallengeReceived) {
						trace.Results["amplification_factor"] = float64(totalDataReceived) / float64(len(initial.Encode(initial.EncodePayload())))

						handshakeResponse := m.NewHandshakePacket(conn)
						handshakeResponse.Frames = append(handshakeResponse.Frames, m.PathResponse{pathChallenge.(*m.PathChallenge).Data}, conn.GetAckFrame())
						conn.SendHandshakeProtectedPacket(handshakeResponse)

						trace.ErrorCode = HR_NoPathChallengeConfirmation  // Assume true unless proven otherwise
						conn.IgnorePathChallenge = false
						if packetFinished != nil {
							conn.SendHandshakeProtectedPacket(packetFinished)
							packetFinished = nil
							conn.SendHTTPGETRequest(preferredUrl, 4)
						}
					}
				} else if pathChallengeReceived == 0 || handshakePacketReceived <= 3 {
					handshakePacketReceivedBeforePC++
					if !ongoingHandshake && handshake.ShouldBeAcknowledged() {
						if packetFinished != nil {
							conn.SendHandshakeProtectedPacket(packetFinished)
							packetFinished = nil
							conn.IgnorePathChallenge = false
						}
						protectedPacket := m.NewProtectedPacket(conn)
						protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
						conn.SendProtectedPacket(protectedPacket)
					}
				}
			} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
				if err := conn.ProcessVersionNegotation(vn); err != nil {
					trace.MarkError(HR_VNDidNotComplete, err.Error(), vn)
					break outerLoop
				}
				initial = conn.GetInitialPacket()
				conn.SendHandshakeProtectedPacket(initial)
				totalDataReceived = 0
			} else if pp, ok := packet.(*m.ProtectedPacket); ok && (isStateless || pathChallengeReceived > 0){
				if pp.ShouldBeAcknowledged() {
					protectedPacket := m.NewProtectedPacket(conn)
					protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
					conn.SendProtectedPacket(protectedPacket)
				}
			} else if _, ok := packet.(*m.RetryPacket); ok {
				isStateless = true
				break outerLoop
			} else {
				continue
			}
		}
	}

	if !isStateless && handshakePacketReceived <= 1 {
		trace.ErrorCode = HR_DidNotRetransmitHandshake
	} else if handshakePacketReceived > 3 && pathChallengeReceived == 0 {
		trace.ErrorCode = HR_NoPathChallengeReceived
	} else if handshakePacketReceived >= 3 && handshakePacketReceivedBeforePC > 0 {
		trace.ErrorCode = HR_NoPathChallengeInAllPackets
	} else if conn.Streams.Get(4).ReadClosed {
		trace.ErrorCode = 0
	}

	trace.Results["arrival_times"] = arrivals
	trace.Results["total_data_received"] = totalDataReceived
	if trace.Results["amplification_factor"] == nil {
		trace.Results["amplification_factor"] = float64(totalDataReceived) / float64(len(initial.Encode(initial.EncodePayload())))
	}
}
