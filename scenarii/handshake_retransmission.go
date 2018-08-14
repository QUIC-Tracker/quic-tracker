package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

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
	return &HandshakeRetransmissionScenario{AbstractScenario{"handshake_retransmission", 3, false, nil}}
}
func (s *HandshakeRetransmissionScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	// TODO: Integrate this scenario with the HandshakeAgent

	/*
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
	packetReceived := 0
	handshakePacketReceivedBeforePC := 0
	var packetFinished qt.Packet = nil

outerLoop:
	for {
		packets, err, rec := conn.ReadNextPackets()

		if err != nil {
			break
		}

		totalDataReceived += len(rec)

		for _, packet := range packets {
			if handshake, ok := packet.(*qt.HandshakePacket); ok {
				var isRetransmit bool
				for _, frame := range handshake.Frames { // TODO Distinguish retransmits-only packets from packets bundling retransmitted and new frames ?
					if streamFrame, ok := frame.(*qt.StreamFrame); ok && streamFrame.StreamId == 0 && streamFrame.Offset == 0 {
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
					var response qt.Packet
					ongoingHandshake, response, err = conn.ProcessServerHello(handshake)
					if err != nil {
						trace.MarkError(HR_TLSHandshakeFailed, err.Error(), response)
						break outerLoop
					}
					if !ongoingHandshake {
						packetFinished = packet
					}
				}

				packetReceived++

				if handshake.Contains(qt.PathChallengeType) {
					pathChallengeReceived++
					if pathChallenge := handshake.GetFirst(qt.PathChallengeType); trace.ErrorCode != HR_NoPathChallengeConfirmation && !ongoingHandshake && (packetReceived < 3 || packetReceived == pathChallengeReceived) {
						trace.Results["amplification_factor"] = float64(totalDataReceived) / float64(len(initial.Encode(initial.EncodePayload())))

						handshakeResponse := qt.NewHandshakePacket(conn)
						handshakeResponse.Frames = append(handshakeResponse.Frames, qt.PathResponse{pathChallenge.(*qt.PathChallenge).Data}, conn.GetAckFrame(packet.PNSpace()))
						conn.SendHandshakeProtectedPacket(handshakeResponse)

						trace.ErrorCode = HR_NoPathChallengeConfirmation  // Assume true unless proven otherwise
						conn.IgnorePathChallenge = false
						if packetFinished != nil {
							conn.SendHandshakeProtectedPacket(packetFinished)
							packetFinished = nil
							conn.SendHTTPGETRequest(preferredUrl, 4)
						}
					}
				} else if pathChallengeReceived == 0 || packetReceived <= 3 {
					handshakePacketReceivedBeforePC++
					if !ongoingHandshake && handshake.ShouldBeAcknowledged() {
						if packetFinished != nil {
							conn.SendHandshakeProtectedPacket(packetFinished)
							packetFinished = nil
							conn.IgnorePathChallenge = false
						}
						protectedPacket := qt.NewProtectedPacket(conn)
						protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(packet.PNSpace()))
						conn.SendProtectedPacket(protectedPacket)
					}
				}
			} else if vn, ok := packet.(*qt.VersionNegotationPacket); ok {
				if err := conn.ProcessVersionNegotation(vn); err != nil {
					trace.MarkError(HR_VNDidNotComplete, err.Error(), vn)
					break outerLoop
				}
				initial = conn.GetInitialPacket()
				conn.SendHandshakeProtectedPacket(initial)
				totalDataReceived = 0
			} else if pp, ok := packet.(*qt.ProtectedPacket); ok && (isStateless || pathChallengeReceived > 0){
				if pp.ShouldBeAcknowledged() {
					protectedPacket := qt.NewProtectedPacket(conn)
					protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(packet.PNSpace()))
					conn.SendProtectedPacket(protectedPacket)
				}
			} else if _, ok := packet.(*qt.RetryPacket); ok {
				isStateless = true
				break outerLoop
			} else {
				continue
			}
		}
	}

	if !isStateless && packetReceived <= 1 {
		trace.ErrorCode = HR_DidNotRetransmitHandshake
	} else if packetReceived > 3 && pathChallengeReceived == 0 {
		trace.ErrorCode = HR_NoPathChallengeReceived
	} else if packetReceived >= 3 && handshakePacketReceivedBeforePC > 0 {
		trace.ErrorCode = HR_NoPathChallengeInAllPackets
	} else if conn.Streams.Get(4).ReadClosed {
		trace.ErrorCode = 0
	}

	trace.Results["arrival_times"] = arrivals
	trace.Results["total_data_received"] = totalDataReceived
	if trace.Results["amplification_factor"] == nil {
		trace.Results["amplification_factor"] = float64(totalDataReceived) / float64(len(initial.Encode(initial.EncodePayload())))
	}
	*/
}
