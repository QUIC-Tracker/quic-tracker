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
	return &ConnectionMigrationScenario{AbstractScenario{"connection_migration", 1, false}}
}
func (s *ConnectionMigrationScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(CM_TLSHandshakeFailed, err.Error(), p)
		return
	}

	conn.UdpConnection.SetDeadline(time.Now().Add(3 * time.Second))

	for p := range conn.IncomingPackets {
		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}
	}

	newUdpConn, err := m.EstablishUDPConnection(conn.Host)
	if err != nil {
		trace.ErrorCode = CM_UDPConnectionFailed
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = newUdpConn

	conn.IncomingPackets = make(chan m.Packet)

	go func() {
		for {
			packets, err, _ := conn.ReadNextPackets()
			if err != nil {
				close(conn.IncomingPackets)
				break
			}
			for _, p := range packets {
				conn.IncomingPackets <- p
			}
		}
	}()

	conn.SendHTTPGETRequest(preferredUrl, 4)
	trace.ErrorCode = CM_HostDidNotMigrate  // Assume it until proven wrong

	for p := range conn.IncomingPackets {
		if trace.ErrorCode == CM_HostDidNotMigrate {
			trace.ErrorCode = CM_HostDidNotValidateNewPath
		}

		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if fp, ok := p.(m.Framer); ok && fp.Contains(m.PathChallengeType) {
			trace.ErrorCode = 0
		}

		if conn.Streams.Get(4).ReadClosed {
			conn.CloseConnection(false, 0, "")
			return
		}
	}
}
