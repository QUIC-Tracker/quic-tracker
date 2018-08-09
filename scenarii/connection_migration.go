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

	"time"
)

const (
	CM_TLSHandshakeFailed        = 1
	CM_UDPConnectionFailed       = 2
	CM_HostDidNotMigrate         = 3
	CM_HostDidNotValidateNewPath = 4
)

type ConnectionMigrationScenario struct {
	AbstractScenario
}

func NewConnectionMigrationScenario() *ConnectionMigrationScenario {
	return &ConnectionMigrationScenario{AbstractScenario{"connection_migration", 1, false, nil}}
}
func (s *ConnectionMigrationScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := s.CompleteHandshake(conn, trace, CM_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C // Wait some time before migrating

	connAgents.Get("SocketAgent").Stop()
	connAgents.Get("SendingAgent").Stop()
	connAgents.Get("SocketAgent").Join()
	connAgents.Get("SendingAgent").Join()

	newUdpConn, err := m.EstablishUDPConnection(conn.Host)
	if err != nil {
		trace.ErrorCode = CM_UDPConnectionFailed
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = newUdpConn

	connAgents.Get("SocketAgent").Run(conn)
	connAgents.Get("SendingAgent").Run(conn)

	conn.EncryptionLevelsAvailable.Submit(m.DirectionalEncryptionLevel{m.EncryptionLevelHandshake, false})  // TODO: Find a way around this
	conn.EncryptionLevelsAvailable.Submit(m.DirectionalEncryptionLevel{m.EncryptionLevel1RTT, false})

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	conn.SendHTTPGETRequest(preferredUrl, 0)
	trace.ErrorCode = CM_HostDidNotMigrate // Assume it until proven wrong

	for {
		select {
		case i := <-incPackets:
			p := i.(m.Packet)
			if trace.ErrorCode == CM_HostDidNotMigrate {
				trace.ErrorCode = CM_HostDidNotValidateNewPath
			}

			if fp, ok := p.(m.Framer); ok && fp.Contains(m.PathChallengeType) {
				trace.ErrorCode = 0
			}

			if conn.Streams.Get(4).ReadClosed {
				conn.CloseConnection(false, 0, "")
			}
		case <-s.Timeout().C:
			return
		}
	}
}
