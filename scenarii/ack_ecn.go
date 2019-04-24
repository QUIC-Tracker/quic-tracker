package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
)

const (
	AE_TLSHandshakeFailed = 1
	AE_FailedToSetECN     = 2
	AE_NonECN             = 3
	AE_NoACKECNReceived   = 4
	AE_NonECNButACKECN    = 5
)

type AckECNScenario struct {
	AbstractScenario
}

func NewAckECNScenario() *AckECNScenario {
	return &AckECNScenario{AbstractScenario{name: "ack_ecn", version: 1}}
}
func (s *AckECNScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, AE_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)
	socketAgent := connAgents.Get("SocketAgent").(*agents.SocketAgent)

	err := socketAgent.ConfigureECN()
	if err != nil {
		trace.MarkError(AE_FailedToSetECN, err.Error(), nil)
		return
	}

	connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)

	trace.ErrorCode = AE_NonECN
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case qt.Framer:
				if p.Contains(qt.AckECNType) {
					if trace.ErrorCode == AE_NonECN {
						trace.ErrorCode = AE_NonECNButACKECN
					} else if trace.ErrorCode == AE_NoACKECNReceived {
						trace.ErrorCode = 0
					}
				}
			}
			switch i.(qt.Packet).ReceiveContext().ECNStatus {
			case qt.ECNStatusNonECT:
			case qt.ECNStatusECT_0, qt.ECNStatusECT_1, qt.ECNStatusCE:
				if trace.ErrorCode == AE_NonECN {
					trace.ErrorCode = AE_NoACKECNReceived
				} else if trace.ErrorCode == AE_NonECNButACKECN {
					trace.ErrorCode = 0
				}
			}
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
