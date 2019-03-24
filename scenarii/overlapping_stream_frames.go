package scenarii

import (
	"bytes"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/davecgh/go-spew/spew"
)

const (
	OSF_TLSHandshakeFailed          = 1
	OSF_StreamBufferHasBeenModified = 2
	OSF_Timedout = 3
)

type OverlappingStreamFramesScenario struct {
	AbstractScenario
}

func NewOverlappingStreamFramesScenario() *OverlappingStreamFramesScenario {
	return &OverlappingStreamFramesScenario{AbstractScenario{name: "overlapping_stream_frames", version: 1, ipv6: false}}
}
func (s *OverlappingStreamFramesScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, OSF_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	conn.SendHTTP09GETRequest(preferredPath, 0)

	f1 := qt.StreamFrame{LenBit: true, StreamId: 4, Length: 3, StreamData: []byte("GO ")}
	data := []byte(fmt.Sprintf("ET %s\r\n", preferredPath))
	f2 := qt.StreamFrame{FinBit: true, LenBit: true, OffBit: true, StreamId: 4, Offset: 1, Length: uint64(len(data)), StreamData: data}

	conn.FrameQueue.Submit(qt.QueuedFrame{f1, qt.EncryptionLevelBestAppData})
	conn.FrameQueue.Submit(qt.QueuedFrame{f2, qt.EncryptionLevelBestAppData})

	s0 := conn.Streams.Get(0)
	s4 := conn.Streams.Get(4)

	trace.ErrorCode = OSF_Timedout
	defer spew.Dump(s0.ReadData, s4.ReadData)

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			if s0.ReadClosed && s4.ReadClosed {
				if bytes.Equal(s0.ReadData, s4.ReadData) {
					trace.ErrorCode = OSF_StreamBufferHasBeenModified
				} else {
					trace.ErrorCode = 0
				}
				s.Finished()
			}
			if p, ok := i.(qt.Framer); ok && (p.Contains(qt.ApplicationCloseType) || p.Contains(qt.ConnectionCloseType)) {
				trace.ErrorCode = 0
				s.Finished()
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}

	if s0.ReadClosed && !s4.ReadClosed {
		trace.ErrorCode = 0
	}
}
