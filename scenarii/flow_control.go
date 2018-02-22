package scenarii

import (
	m "masterthesis"
)

const (
	FC_TLSHandshakeFailed      = 1
	FC_HostSentMoreThanLimit   = 2
	FC_HostDidNotResumeSending = 3
)

type FlowControlScenario struct {
	AbstractScenario
}
func NewFlowControlScenario() *FlowControlScenario {
	return &FlowControlScenario{AbstractScenario{"flow_control", 1, false}}
}
func (s *FlowControlScenario) Run(conn *m.Connection, trace *m.Trace) {
	if err := CompleteHandshake(conn); err != nil {
		trace.ErrorCode = FC_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
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

		if conn.Streams[4].ReadOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
			trace.ErrorCode = FC_HostSentMoreThanLimit
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket = m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := packet.(m.ProtectedPacket); ok {
			var isBlocked bool
			for _, frame := range pp.Frames {
				_, isGloballyBlocked := frame.(m.BlockedFrame)
				_, isStreamBlocked := frame.(m.StreamBlockedFrame)
				isBlocked = isGloballyBlocked || isStreamBlocked
				if isBlocked {
					break
				}
			}
			if isBlocked {
				maxData := m.MaxDataFrame{uint64(conn.TLSTPHandler.MaxData * 2)}
				maxStreamData := m.MaxStreamDataFrame{4,uint64(conn.TLSTPHandler.MaxStreamData * 2)}
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, maxData, maxStreamData)
				break
			}

			// TODO: Check that the host resumes sending after setting higher limits

		}
	}

	conn.CloseConnection(false, 42, "")
}
