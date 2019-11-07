package scenarii

import (
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"strings"

	"time"
)

const (
	SOR_TLSHandshakeFailed       = 1
	SOR_HostDidNotRespond        = 2
	SOR_EndpointDoesNotSupportHQ = 3
)

type StreamOpeningReorderingScenario struct {
	AbstractScenario
}

func NewStreamOpeningReorderingScenario() *StreamOpeningReorderingScenario {
	return &StreamOpeningReorderingScenario{AbstractScenario{name: "stream_opening_reordering", version: 2}}
}
func (s *StreamOpeningReorderingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	if !strings.Contains(conn.ALPN, "hq") {
		trace.ErrorCode = SOR_EndpointDoesNotSupportHQ
		return
	}

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	payload := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(0, 0, payload, false))

	pp2 := qt.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(0, uint64(len(payload)), []byte{}, true))

	conn.DoSendPacket(pp2, qt.EncryptionLevel1RTT)
	conn.DoSendPacket(pp1, qt.EncryptionLevel1RTT)

forLoop:
	for {
		select {
		case <-incomingPackets:
			if conn.Streams.Get(0).ReadClosed {
				s.Finished()
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = SOR_HostDidNotRespond
	}
}
