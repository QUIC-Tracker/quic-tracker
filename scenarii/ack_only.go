package scenarii

import (
	m "masterthesis"
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
func (s *AckOnlyScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.TLSTPHandler.MaxStreamData = 80

	if err := CompleteHandshake(conn); err != nil {
		trace.ErrorCode = AO_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	conn.Streams[4] = &m.Stream{}
	streamFrame := m.NewStreamFrame(4, conn.Streams[4], []byte("GET /\r\n"), false)
	ackFrame := conn.GetAckFrame()

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame, ackFrame)
	conn.SendProtectedPacket(protectedPacket)

	var ackOnlyPackets []uint64

testCase:
	for {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			trace.Results["error"] = err.Error()
			return
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket = m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
			ackOnlyPackets = append(ackOnlyPackets, uint64(protectedPacket.Header().PacketNumber()))
		}

		if pp, ok := packet.(*m.ProtectedPacket); ok && !packet.ShouldBeAcknowledged() {
			for _, frame := range pp.Frames {
				if ack, ok := frame.(*m.AckFrame); ok {
					for _, ackOnlyPacket := range ackOnlyPackets {
						if ack.LargestAcknowledged == ackOnlyPacket {
							trace.ErrorCode = AO_SentAOInResponseOfAO
							break testCase
						}
					}
				}
			}
		}
	}

	conn.CloseConnection(false, 42, "")
}
