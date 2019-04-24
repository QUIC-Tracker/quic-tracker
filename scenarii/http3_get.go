package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
)

const (
	H3G_TLSHandshakeFailed = 1
	H3G_RequestTimeout     = 2
	H3G_NotEnoughStreamsAvailable = 3
)

type HTTP3GETScenario struct {
	AbstractScenario
}

func NewHTTP3GETScenario() *HTTP3GETScenario {
	return &HTTP3GETScenario{AbstractScenario{name: "http3_get", version: 1, http3: true}}
}
func (s *HTTP3GETScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxUniStreams = 3

	http := agents.HTTP3Agent{}
	connAgents := s.CompleteHandshake(conn, trace, H3G_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3G_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	responseReceived := http.SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = H3G_RequestTimeout
	select {
	case <-responseReceived:
		trace.ErrorCode = 0
		s.Finished()
		<-s.Timeout()
	case <-conn.ConnectionClosed:
		return
	case <-s.Timeout():
		return
	}
}
