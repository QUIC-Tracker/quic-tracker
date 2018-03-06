package scenarii

import (
	m "masterthesis"
)

const (
	FC_TLSHandshakeFailed          = 1
	FC_HostSentMoreThanLimit       = 2
	FC_HostDidNotResumeSending     = 3
	FC_NotEnoughDataAvailable      = 4
	FC_RespectedLimitsButNoBlocked = 5
)

type FlowControlScenario struct {
	AbstractScenario
}
func NewFlowControlScenario() *FlowControlScenario {
	return &FlowControlScenario{AbstractScenario{"flow_control", 1, false}}
}
func (s *FlowControlScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.TLSTPHandler.MaxStreamData = 80

	if err := CompleteHandshake(conn); err != nil {
		trace.ErrorCode = FC_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	conn.Streams[4] = &m.Stream{}
	streamFrame := m.NewStreamFrame(4, conn.Streams[4], []byte("GET /\r\n"), false)
	ackFrame := conn.GetAckFrame()

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame, ackFrame)
	conn.SendProtectedPacket(protectedPacket)

	var shouldResume bool
	var isBlocked bool

	for {
		packet, err, _ := conn.ReadNextPacket()
		if shouldResume {
			// TODO
		}
		if err != nil {
			readOffset := conn.Streams[4].ReadOffset
			if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) && !isBlocked {
				trace.ErrorCode = FC_RespectedLimitsButNoBlocked
			} else if shouldResume && readOffset == uint64(conn.TLSTPHandler.MaxStreamData) / 2 {
				trace.ErrorCode = FC_HostDidNotResumeSending
			} else if readOffset < uint64(conn.TLSTPHandler.MaxStreamData) {
				trace.ErrorCode = FC_NotEnoughDataAvailable
			}
			trace.Results["error"] = err.Error()
			return
		}

		if conn.Streams[4].ReadOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
			trace.ErrorCode = FC_HostSentMoreThanLimit
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket = m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := packet.(*m.ProtectedPacket); ok {
			for _, frame := range pp.Frames {
				_, isGloballyBlocked := frame.(*m.BlockedFrame)
				_, isStreamBlocked := frame.(*m.StreamBlockedFrame)
				isBlocked = isGloballyBlocked || isStreamBlocked
				if isBlocked {
					break
				}
			}
			if isBlocked && !shouldResume {
				maxData := m.MaxDataFrame{uint64(conn.TLSTPHandler.MaxData * 2)}
				conn.TLSTPHandler.MaxData *= 2
				maxStreamData := m.MaxStreamDataFrame{4,uint64(conn.TLSTPHandler.MaxStreamData * 2)}
				conn.TLSTPHandler.MaxStreamData *= 2
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, maxData, maxStreamData)
				conn.SendProtectedPacket(protectedPacket)
				shouldResume = true
			}
		}
	}

	conn.CloseConnection(false, 42, "")
}
