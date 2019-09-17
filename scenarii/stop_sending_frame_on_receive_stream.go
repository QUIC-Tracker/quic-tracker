package scenarii

import (
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
)

const (
	SSRS_TLSHandshakeFailed               = 1
	SSRS_DidNotCloseTheConnection         = 2
	SSRS_CloseTheConnectionWithWrongError = 3
	SSRS_MaxStreamUniTooLow               = 4
	SSRS_UnknownError                     = 5
)

type StopSendingOnReceiveStreamScenario struct {
	AbstractScenario
}

func NewStopSendingOnReceiveStreamScenario() *StopSendingOnReceiveStreamScenario {
	return &StopSendingOnReceiveStreamScenario{AbstractScenario{name: "stop_sending_frame_on_receive_stream", version: 1}}
}

func (s *StopSendingOnReceiveStreamScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, SSRS_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams == 0 {
		trace.MarkError(SSRS_MaxStreamUniTooLow, "", nil)
		return
	}

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	conn.SendHTTP09GETRequest(preferredPath, 2)
	conn.FrameQueue.Submit(qt.QueuedFrame{&qt.StopSendingFrame{2, 0}, qt.EncryptionLevel1RTT})

	trace.ErrorCode = SSRS_DidNotCloseTheConnection
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case qt.Framer:
				if p.Contains(qt.ConnectionCloseType) {
					cc := p.GetFirst(qt.ConnectionCloseType).(*qt.ConnectionCloseFrame)
					if cc.ErrorCode != qt.ERR_STREAM_STATE_ERROR && cc.ErrorCode != qt.ERR_PROTOCOL_VIOLATION {
						trace.MarkError(SSRS_CloseTheConnectionWithWrongError, fmt.Sprintf("Expected 0x%02x, got 0x%02x", qt.ERR_STREAM_STATE_ERROR, cc.ErrorCode), p)
						trace.Results["connection_closed_error_code"] = fmt.Sprintf("0x%x", cc.ErrorCode)
						return
					}
					trace.ErrorCode = 0
					return
				}
			}
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
