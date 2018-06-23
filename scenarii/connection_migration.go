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
	"net"
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
	if _, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(CM_TLSHandshakeFailed, err.Error())
		return
	}

	conn.UdpConnection.SetDeadline(time.Now().Add(3 * time.Second))

	for {  // Acks and restransmits if needed
		packets, err, _ := conn.ReadNextPackets()

		if nerr, ok := err.(*net.OpError); ok && nerr.Timeout() {
			break
		} else if err != nil {
			trace.Results["error"] = err.Error()
		}

		for _, packet := range packets {

			if packet.ShouldBeAcknowledged() {
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(protectedPacket)
			}
		}
	}

	newUdpConn, err := m.EstablishUDPConnection(conn.Host)
	if err != nil {
		trace.ErrorCode = CM_UDPConnectionFailed
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = newUdpConn

	conn.SendHTTPGETRequest(preferredUrl, 4)
	trace.ErrorCode = CM_HostDidNotMigrate  // Assume it until proven wrong

	for {
		packets, err, _ := conn.ReadNextPackets()

		if err != nil {
			trace.Results["error"] = err.Error()
			break
		}

		if trace.ErrorCode == CM_HostDidNotMigrate {
			trace.ErrorCode = CM_HostDidNotValidateNewPath
		}

		for _, packet := range packets {
			if packet.ShouldBeAcknowledged() {
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(protectedPacket)
			}

			if fp, ok := packet.(m.Framer); ok && fp.Contains(m.PathChallengeType) {
				trace.ErrorCode = 0
			}

			if conn.Streams.Get(4).ReadClosed {
				conn.CloseConnection(false, 0, "")
				return
			}
		}
	}
}
