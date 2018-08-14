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
	qt "github.com/QUIC-Tracker/quic-tracker"
	"fmt"

	"time"
)

const (
	SOR_TLSHandshakeFailed = 1
	SOR_HostDidNotRespond  = 2
)

type StreamOpeningReorderingScenario struct {
	AbstractScenario
}

func NewStreamOpeningReorderingScenario() *StreamOpeningReorderingScenario {
	return &StreamOpeningReorderingScenario{AbstractScenario{"stream_opening_reordering", 2, false, nil}}
}
func (s *StreamOpeningReorderingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, SOR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	<-time.NewTimer(20 * time.Millisecond).C // Simulates the SendingAgent behaviour

	pp1 := qt.NewProtectedPacket(conn)
	pp1.Frames = append(pp1.Frames, qt.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", preferredUrl)), false))

	pp2 := qt.NewProtectedPacket(conn)
	pp2.Frames = append(pp2.Frames, qt.NewStreamFrame(4, conn.Streams.Get(4), []byte{}, true))

	conn.SendPacket(pp2, qt.EncryptionLevel1RTT)
	conn.SendPacket(pp1, qt.EncryptionLevel1RTT)

	<-s.Timeout().C

	if !conn.Streams.Get(4).ReadClosed {
		trace.ErrorCode = SOR_HostDidNotRespond
	}
}
