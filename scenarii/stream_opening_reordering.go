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
	"fmt"
)

const (
	SOR_TLSHandshakeFailed = 1
	SOR_HostDidNotRespond  = 2
)

type StreamOpeningReorderingScenario struct {
	AbstractScenario
}

func NewStreamOpeningReorderingScenario() *StreamOpeningReorderingScenario {
	return &StreamOpeningReorderingScenario{AbstractScenario{"stream_opening_reordering", 2, false}}
}
func (s *StreamOpeningReorderingScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(SOR_TLSHandshakeFailed, "", p)
		return
	}

	pp1 := m.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, m.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", preferredUrl)), false))

	pp2 := m.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, m.NewStreamFrame(4, conn.Streams.Get(4), []byte{}, true))

	conn.SendProtectedPacket(pp2)
	conn.SendProtectedPacket(pp1)

	for p := range conn.IncomingPackets {
		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if conn.Streams.Get(4).ReadClosed {
			break
		}
	}

	conn.CloseConnection(false, 0, "")
	if !conn.Streams.Get(4).ReadClosed {
		trace.ErrorCode = SOR_HostDidNotRespond
	}

}
