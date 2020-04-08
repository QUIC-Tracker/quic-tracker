package scenarii

import (
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
)

const (
	SFC_TLSHandshakeFailed = 1
	SFC_DidNotClose = 2
)

type ServerFlowControlScenario struct {
	AbstractScenario
}

func NewServerFlowControlScenario() *ServerFlowControlScenario {
	return &ServerFlowControlScenario{AbstractScenario{name: "server_flow_control", version: 1}}
}
func (s *ServerFlowControlScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, SFC_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	data := []byte(fmt.Sprintf("GET %s\r\n", preferredPath))
	f := qt.StreamFrame{
		FinBit: true, LenBit: true, OffBit: true,
		StreamId: 0,
		Offset:   conn.TLSTPHandler.ReceivedParameters.MaxStreamDataBidiRemote - uint64(len(data)) + 1,
		Length:   uint64(len(data)), StreamData: data,
	}

	conn.FrameQueue.Submit(qt.QueuedFrame{&f, qt.EncryptionLevelBestAppData})

	trace.ErrorCode = SFC_DidNotClose
	for {
		select {
		case i := <-incPackets:
			if p, ok := i.(qt.Framer); ok && (p.Contains(qt.ConnectionCloseType)) {
				cc := p.GetFirst(qt.ConnectionCloseType).(*qt.ConnectionCloseFrame)
				if cc.ErrorCode == 0x3 {
					trace.ErrorCode = 0
				} else if cc.ErrorCode & 0x100 == 0x100 {
					trace.ErrorCode = SFC_TLSHandshakeFailed
				}
				s.Finished()
			}
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
