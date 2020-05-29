package scenarii

import qt "github.com/QUIC-Tracker/quic-tracker"

const (
	ZLCID_TLSHandshakeFailed = 1
	ZLCID_RequestFailed = 2
)

type ZeroLengthCID struct {
	AbstractScenario
}

func NewZeroLengthCID() *ZeroLengthCID {
	return &ZeroLengthCID{AbstractScenario{name: "zero_length_cid", version: 1}}
}

func (s *ZeroLengthCID) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.SourceCID = nil
	conn.TLSTPHandler.InitialSourceConnectionId = nil
	connAgents := s.CompleteHandshake(conn, trace, ZLCID_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)

	<-s.Timeout()

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = ZLCID_RequestFailed
	}
}

