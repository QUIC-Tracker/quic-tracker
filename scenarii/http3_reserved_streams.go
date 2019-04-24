package scenarii

import (
	"bytes"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"github.com/QUIC-Tracker/quic-tracker/http3"
)

const (
	H3RS_TLSHandshakeFailed = 1
	H3RS_RequestTimeout = 2
	H3RS_NotEnoughStreamsAvailable = 3
)

type HTTP3ReservedStreamsScenario struct {
	AbstractScenario
}

func NewHTTP3ReservedStreamsScenario() *HTTP3ReservedStreamsScenario {
	return &HTTP3ReservedStreamsScenario{AbstractScenario{name: "http3_reserved_streams", version: 1, ipv6: false, http3: true}}
}
func (s *HTTP3ReservedStreamsScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxUniStreams = 3

	http := agents.HTTP3Agent{DisableQPACKStreams: true}
	connAgents := s.CompleteHandshake(conn, trace, H3RS_TLSHandshakeFailed, &http)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams < 3 || conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams == 0 {
		trace.ErrorCode = H3RS_NotEnoughStreamsAvailable
		trace.Results["max_uni_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxUniStreams
		trace.Results["max_bidi_streams"] = conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams
		return
	}

	payload := []byte("Hello, world!")
	unknownFrame1 := http3.UnknownFrame{HTTPFrameHeader: http3.HTTPFrameHeader{Type: qt.NewVarInt(0x21), Length: qt.NewVarInt(uint64(len(payload)))}, OpaquePayload: payload}
	unknownFrame2 := http3.UnknownFrame{HTTPFrameHeader: http3.HTTPFrameHeader{Type: qt.NewVarInt(0x21 + 0x1f), Length: qt.NewVarInt(0)}}

	buf := new(bytes.Buffer)
	unknownFrame1.WriteTo(buf)
	unknownFrame2.WriteTo(buf)

	conn.Streams.Send(6, []byte{0x21}, false)
	conn.Streams.Send(10, []byte{0x21 + (0x1f * 3)}, false)
	conn.Streams.Send(6, buf.Bytes(), false)
	conn.Streams.Send(10, buf.Bytes(), false)

	responseReceived := http.SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = H3RS_RequestTimeout
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
