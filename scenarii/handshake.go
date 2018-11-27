package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"github.com/QUIC-Tracker/quic-tracker/agents"
	"time"
)

const (
	H_ReceivedUnexpectedPacketType = 1
	H_TLSHandshakeFailed           = 2
	H_NoCompatibleVersionAvailable = 3
	H_Timeout                      = 4
)

type HandshakeScenario struct {
	AbstractScenario
}

func NewHandshakeScenario() *HandshakeScenario {
	return &HandshakeScenario{AbstractScenario{"handshake", 2, false, nil}}
}
func (s *HandshakeScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)

	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)
	handshakeAgent.InitiateHandshake()

	var status agents.HandshakeStatus
	for {
		select {
		case i := <-handshakeStatus:
			status = i.(agents.HandshakeStatus)
			if !status.Completed {
				switch status.Error.Error() {
				case "no appropriate version found":
					trace.MarkError(H_NoCompatibleVersionAvailable, status.Error.Error(), status.Packet)
				case "received incorrect packet type during handshake":
					trace.MarkError(H_ReceivedUnexpectedPacketType, "", status.Packet)
				default:
					trace.MarkError(H_TLSHandshakeFailed, status.Error.Error(), status.Packet)
				}
			} else {
				trace.Results["negotiated_version"] = conn.Version
			}
			handshakeAgent.HandshakeStatus.Unregister(handshakeStatus)
		case <-s.Timeout().C:
			if !status.Completed {
				trace.MarkError(H_Timeout, "", nil)
				connAgents.StopAll()
			} else {
				connAgents.CloseConnection(false, 0, "")
			}
			return
		}
	}
}
