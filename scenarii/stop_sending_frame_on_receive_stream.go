package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"fmt"

	"time"
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
	return &StopSendingOnReceiveStreamScenario{AbstractScenario{"stop_sending_frame_on_receive_stream", 1, false, nil}}
}

func (s *StopSendingOnReceiveStreamScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, SSRS_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams == 0 {
		trace.MarkError(SSRS_MaxStreamUniTooLow, "", nil)
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)
	conn.FrameQueue.Submit(qt.QueuedFrame{&qt.StopSendingFrame{2, 0}, qt.EncryptionLevel1RTT})

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	trace.ErrorCode = SSRS_DidNotCloseTheConnection
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case qt.Framer:
				if p.Contains(qt.ConnectionCloseType) {
					cc := p.GetFirst(qt.ConnectionCloseType).(*qt.ConnectionCloseFrame)
					if cc.ErrorCode != qt.ERR_PROTOCOL_VIOLATION {
						trace.MarkError(SSRS_CloseTheConnectionWithWrongError, "", p)
						trace.Results["connection_closed_error_code"] = fmt.Sprintf("0x%x", cc.ErrorCode)
						return
					}
					trace.ErrorCode = 0
					return
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
