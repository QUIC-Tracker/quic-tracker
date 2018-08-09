/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package scenarii

import (
	m "github.com/mpiraux/master-thesis"

	"github.com/mpiraux/master-thesis/agents"
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
func (s *HandshakeScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	defer connAgents.StopAll()
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent)}
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
				defer connAgents.CloseConnection(false, 0, "")
			}
			handshakeAgent.HandshakeStatus.Unregister(handshakeStatus)
		case <-s.Timeout().C:
			if !status.Completed {
				trace.MarkError(H_Timeout, "", nil)
			}
		}
	}
}
