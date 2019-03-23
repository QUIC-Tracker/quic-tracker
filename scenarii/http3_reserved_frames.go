package scenarii

import (
	"bytes"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"github.com/QUIC-Tracker/quic-tracker/http3"
)

const (
	H3RF_TLSHandshakeFailed = 1
	H3RF_RequestTimeout = 2
	H3RF_NotEnoughStreamsAvailable = 3
)

type HTTP3ReservedFramesScenario struct {
	AbstractScenario
}

func NewHTTP3ReservedFramesScenario() *HTTP3ReservedFramesScenario {
	return &HTTP3ReservedFramesScenario{AbstractScenario{name: "http3_reserved_frames", version: 1, ipv6: false, http3: true}}
}
func (s *HTTP3ReservedFramesScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxUniStreams = 3

	http := agents.HTTPAgent{}
	connAgents := s.CompleteHandshake(conn, trace, H3RF_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3RF_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	payload := []byte("Hello, world!")
	unknownFrame1 := http3.UnknownFrame{http3.HTTPFrameHeader{qt.NewVarInt(uint64(len(payload))), 0xb}, payload}
	unknownFrame2 := http3.UnknownFrame{http3.HTTPFrameHeader{qt.NewVarInt(0), 0xb + 0x1f}, nil}

	buf := new(bytes.Buffer)
	unknownFrame1.WriteTo(buf)
	unknownFrame2.WriteTo(buf)

	conn.StreamInput.Submit(qt.StreamInput{StreamId: 0, Data: buf.Bytes()})

	responseReceived := http.HTTPResponseReceived.RegisterNewChan(1000)

	http.SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = H3RF_RequestTimeout
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
