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

	http := agents.HTTP3Agent{}
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
	unknownFrame1 := http3.UnknownFrame{HTTPFrameHeader: http3.HTTPFrameHeader{Type: qt.NewVarInt(0x21), Length: qt.NewVarInt(uint64(len(payload)))}, OpaquePayload: payload}
	unknownFrame2 := http3.UnknownFrame{HTTPFrameHeader: http3.HTTPFrameHeader{Type: qt.NewVarInt(0x21 + 0x1f), Length: qt.NewVarInt(0)}}

	buf := new(bytes.Buffer)
	unknownFrame1.WriteTo(buf)
	unknownFrame2.WriteTo(buf)

	conn.Streams.Send(0, buf.Bytes(), false)

	responseReceived := http.SendRequest(preferredPath, "GET", trace.Host, nil)

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
