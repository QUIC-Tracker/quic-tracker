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
func (s *HTTP3EncoderStreamScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	conn.TLSTPHandler.MaxUniStreams = 3

	http := agents.HTTPAgent{QPACKEncoderOpts: ls_qpack_go.LSQPackEncOptIxAggr}
	connAgents := s.CompleteHandshake(conn, trace, H3ES_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3ES_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	frameReceived := make(chan interface{}, 1000)
	http.FrameReceived.Register(frameReceived)

	responseReceived := make(chan interface{}, 1000)
	http.HTTPResponseReceived.Register(responseReceived)

forLoop:
	for {
		select {
		case i := <-frameReceived:
			fr := i.(agents.HTTPFrameReceived)
			switch fr.Frame.(type) {
			case *http3.SETTINGS:
				break forLoop
			}
		case <-s.Timeout().C:
			trace.ErrorCode = H3ES_SETTINGSNotSent
			return
		}
	}

	<-time.NewTimer(200 * time.Millisecond).C
	http.SendRequest(preferredUrl, "GET", trace.Host, nil)

	select {
	case <-responseReceived:
		trace.ErrorCode = 0
		<-s.Timeout().C
	case <-s.Timeout().C:
		trace.ErrorCode = H3ES_RequestTimeout
		return
	}
}
