package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"github.com/QUIC-Tracker/quic-tracker/http3"
	"github.com/mpiraux/ls-qpack-go"
	"time"
)

const (
	H3ES_TLSHandshakeFailed        = 1
	H3ES_RequestTimeout            = 2
	H3ES_NotEnoughStreamsAvailable = 3
	H3ES_SETTINGSNotSent           = 4
)

type HTTP3EncoderStreamScenario struct {
	AbstractScenario
}

func NewHTTP3EncoderStreamScenario() *HTTP3EncoderStreamScenario {
	return &HTTP3EncoderStreamScenario{AbstractScenario{name: "http3_encoder_stream", version: 1, http3: true}}
}
func (s *HTTP3EncoderStreamScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxUniStreams = 3

	http := agents.HTTP3Agent{QPACKEncoderOpts: ls_qpack_go.LSQPackEncOptIxAggr}
	connAgents := s.CompleteHandshake(conn, trace, H3ES_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")
	frameReceived := http.FrameReceived.RegisterNewChan(1000)

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3ES_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	if http.ReceivedSettings == nil {
	forLoop:
		for {
			select {
			case i := <-frameReceived:
				fr := i.(agents.HTTP3FrameReceived)
				switch fr.Frame.(type) {
				case *http3.SETTINGS:
					break forLoop
				}
			case <-conn.ConnectionClosed:
				return
			case <-s.Timeout():
				trace.ErrorCode = H3ES_SETTINGSNotSent
				return
			}
		}
	}

	<-time.NewTimer(200 * time.Millisecond).C
	responseReceived := http.SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = H3ES_RequestTimeout
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
