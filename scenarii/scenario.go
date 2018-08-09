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

type Scenario interface {
	Name() string
	Version() int
	IPv6() bool
	Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool)
	Timeout() *time.Timer
}

type AbstractScenario struct {
	name    string
	version int
	ipv6    bool
	timeout *time.Timer
}
func (s *AbstractScenario) Name() string {
	return s.name
}
func (s *AbstractScenario) Version() int {
	return s.version
}
func (s *AbstractScenario) IPv6() bool {
	return s.ipv6
}
func (s *AbstractScenario) Timeout() *time.Timer {
	return s.timeout
}
func (s *AbstractScenario) CompleteHandshake(conn *m.Connection, trace *m.Trace, handshakeErrorCode uint8, additionalAgents ...agents.Agent) *agents.ConnectionAgents {
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent)}
	connAgents.Add(handshakeAgent)

	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)
	handshakeAgent.InitiateHandshake()

	select {
	case i := <-handshakeStatus:
		status := i.(agents.HandshakeStatus)
		if !status.Completed {
			trace.MarkError(handshakeErrorCode, status.Error.Error(), status.Packet)
			connAgents.StopAll()
			return nil
		}
	case <-s.Timeout().C:
		trace.MarkError(handshakeErrorCode, "handshake timeout", nil)
		connAgents.StopAll()
		return nil
	}
	return connAgents
}

func CompleteHandshake(conn *m.Connection) (m.Packet, error) {
	return nil, nil
}