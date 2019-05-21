package scenarii

import (
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	_ "github.com/davecgh/go-spew/spew"
)

const (
	MS_TLSHandshakeFailed      = 1
	MS_NoTPReceived            = 2 // We don't distinguish the two first cases anymore
	MS_NotAllStreamsWereClosed = 3
)

type MultiStreamScenario struct {
	AbstractScenario
}

func NewMultiStreamScenario() *MultiStreamScenario {
	return &MultiStreamScenario{AbstractScenario{name: "multi_stream", version: 1}}
}
func (s *MultiStreamScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.MaxData = 1024 * 1024
	conn.TLSTPHandler.MaxStreamDataBidiLocal = 1024 * 1024 / 10

	allClosed := true
	connAgents := s.CompleteHandshake(conn, trace, MS_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	httpAgent := connAgents.AddHTTPAgent()
	for i := uint64(0); i < conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams && i < 4; i++ {
		httpAgent.SendRequest(preferredPath, "GET", trace.Host, nil)
	}

forLoop:
	for {
		select {
		case <-incPackets:
			for streamId, stream := range conn.Streams.GetAll() {
				if qt.IsBidi(streamId) && !stream.ReadClosed {
					allClosed = false
					break
				}
			}

			if allClosed {
				s.Finished()
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}

	allClosed = true
	for streamId, stream := range conn.Streams.GetAll() {
		if qt.IsBidi(streamId) && !stream.ReadClosed {
			allClosed = false
			break
		}
	}

	if !allClosed {
		trace.ErrorCode = MS_NotAllStreamsWereClosed
		for streamId, stream := range conn.Streams.GetAll() {
			if qt.IsBidi(streamId) {
				trace.Results[fmt.Sprintf("stream_%d_rec_offset", streamId)] = stream.ReadOffset
				trace.Results[fmt.Sprintf("stream_%d_snd_offset", streamId)] = stream.WriteOffset
				trace.Results[fmt.Sprintf("stream_%d_snd_closed", streamId)] = stream.WriteClosed
				trace.Results[fmt.Sprintf("stream_%d_rec_closed", streamId)] = stream.ReadClosed
			}
		}
	}
}
