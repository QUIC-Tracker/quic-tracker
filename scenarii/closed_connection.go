package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"time"
)

const (
	CCS_TLSHandshakeFailed = 1
	CCS_NoPacketsReceived = 2
	CSS_APacketWasReceived = 3
)

type ClosedConnectionScenario struct {
	AbstractScenario
}

func NewClosedConnectionScenario() *ClosedConnectionScenario {
	return &ClosedConnectionScenario{AbstractScenario{name: "closed_connection", version: 1}}
}
func (s *ClosedConnectionScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, CCS_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	<-time.NewTimer(time.Duration(2 * conn.SmoothedRTT) * time.Microsecond).C
	conn.CloseConnection(false, 0, "")
	<-time.NewTimer(time.Duration(8 * conn.SmoothedRTT) * time.Microsecond).C

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	for i := 0; i < 3; i++ {
		ping := qt.PingFrame(0)
		conn.FrameQueue.Submit(qt.QueuedFrame{&ping, qt.EncryptionLevel1RTT})
		<-time.NewTimer(time.Duration(3 * conn.SmoothedRTT) * time.Microsecond).C
	}

	trace.ErrorCode = CCS_NoPacketsReceived
	for {
		select {
		case <-incomingPackets:
			trace.ErrorCode = CSS_APacketWasReceived
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
