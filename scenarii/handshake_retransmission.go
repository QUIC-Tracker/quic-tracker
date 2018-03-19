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
	"github.com/davecgh/go-spew/spew"
)

const (
	HR_DidNotRetransmitHandshake = 1
	HR_VNDidNotComplete          = 2
)

type HandshakeRetransmissionScenario struct {
	AbstractScenario
}
func NewHandshakeRetransmissionScenario() *HandshakeRetransmissionScenario {
	return &HandshakeRetransmissionScenario{AbstractScenario{"handshake_retransmission", 1, false}}
}
func (s *HandshakeRetransmissionScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	conn.SendInitialPacket()

	arrivals := make([]uint64, 0, 10)

	var start time.Time
	for  i := 0; i < 20; i++ {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			break
		}

		if handshake, ok := packet.(*m.HandshakePacket); ok {
			var isRetransmit bool
			for _, frame := range handshake.StreamFrames {  // TODO Distinguish retransmits-only packets from packets bundling retransmitted and new frames ?
				if frame.StreamId == 0 && frame.Offset == 0 {
					isRetransmit = true
					break
				}
			}
			if !isRetransmit {
				continue
			}
			if start.IsZero() {
				start = time.Now()
			}
			arrivals = append(arrivals, uint64(time.Now().Sub(start).Seconds()*1000))
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err != nil {
				trace.MarkError(HR_VNDidNotComplete, err.Error())
				return
			}
			conn.SendInitialPacket()
		} else {
			spew.Dump(packet)
			return
		}
	}

	if len(arrivals) == 1 {
		trace.ErrorCode = HR_DidNotRetransmitHandshake
	}
	trace.Results["arrival_times"] = arrivals

}
