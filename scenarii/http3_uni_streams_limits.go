package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
)

const (
	H3USFC_TLSHandshakeFailed        = 1
	H3USFC_RequestTimeout            = 2
	H3USFC_NotEnoughStreamsAvailable = 3
	H3USFC_StreamIDError             = 4
)

type HTTP3UniStreamsLimitsScenario struct {
	AbstractScenario
}

func NewHTTP3UniStreamsLimitsScenario() *HTTP3UniStreamsLimitsScenario {
	return &HTTP3UniStreamsLimitsScenario{AbstractScenario{name: "http3_uni_streams_limits", version: 1, http3: true}}
}
func (s *HTTP3UniStreamsLimitsScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxUniStreams = 1

	http := agents.HTTP3Agent{}
	connAgents := s.CompleteHandshake(conn, trace, H3USFC_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3USFC_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	responseReceived := http.SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = H3USFC_RequestTimeout
	select {
	case <-responseReceived:
		trace.ErrorCode = 0
		s.Finished()
		<-s.Timeout()
	case <-conn.ConnectionClosed:
	case <-s.Timeout():
	}

	if conn.Streams.NumberOfServerStreamsOpen() > 1 {
		trace.ErrorCode = H3USFC_StreamIDError
	}
}
