package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"time"
)

const (
	GS2_TLSHandshakeFailed                    = 1
	GS2_TooLowStreamIdUniToSendRequest        = 2
	GS2_ReceivedDataOnStream2                 = 3
	GS2_ReceivedDataOnUnauthorizedStream      = 4
	GS2_AnswersToARequestOnAForbiddenStreamID = 5 // This is hard to disambiguate sometimes, we don't check anymore
	GS2_DidNotCloseTheConnection              = 6
)

type GetOnStream2Scenario struct {
	AbstractScenario
}

func NewGetOnStream2Scenario() *GetOnStream2Scenario {
	return &GetOnStream2Scenario{AbstractScenario{"http_get_on_uni_stream", 1, false, nil}}
}

func (s *GetOnStream2Scenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	conn.TLSTPHandler.MaxBidiStreams = 1
	conn.TLSTPHandler.MaxUniStreams = 1

	connAgents := s.CompleteHandshake(conn, trace, GS2_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	trace.Results["received_transport_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON
	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams == 0 {
		trace.ErrorCode = GS2_DidNotCloseTheConnection
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)

	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case *qt.ProtectedPacket:
				for _, f := range p.Frames {
					switch f := f.(type) {
					case *qt.StreamFrame:
						if f.StreamId == 2 {
							trace.MarkError(GS2_ReceivedDataOnStream2, "", p)
							return
						} else if f.StreamId > 3 {
							trace.MarkError(GS2_ReceivedDataOnUnauthorizedStream, "", p)
							return
						}
					case *qt.ConnectionCloseFrame:
						if trace.ErrorCode == GS2_DidNotCloseTheConnection && f.ErrorCode == qt.ERR_STREAM_ID_ERROR || f.ErrorCode == qt.ERR_PROTOCOL_VIOLATION {
							trace.ErrorCode = GS2_TooLowStreamIdUniToSendRequest
						}
						return
					}
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
