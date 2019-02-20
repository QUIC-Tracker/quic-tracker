package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"fmt"

	"time"
)

const (
	SOR_TLSHandshakeFailed = 1
	SOR_HostDidNotRespond  = 2
)

type StreamOpeningReorderingScenario struct {
	AbstractScenario
}

func NewStreamOpeningReorderingScenario() *StreamOpeningReorderingScenario {
	return &StreamOpeningReorderingScenario{AbstractScenario{name: "stream_opening_reordering", version: 2}}
}
func (s *StreamOpeningReorderingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	payload := []byte(fmt.Sprintf("GET %s\r\n", preferredUrl))

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(0, 0, payload, false))

	pp2 := qt.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(0, uint64(len(payload)), []byte{}, true))

	conn.SendPacket(pp2, qt.EncryptionLevel1RTT)
	conn.SendPacket(pp1, qt.EncryptionLevel1RTT)

	<-s.Timeout().C

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = SOR_HostDidNotRespond
	}
}
