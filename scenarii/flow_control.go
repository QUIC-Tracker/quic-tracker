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
)

const (
	FC_TLSHandshakeFailed          = 1
	FC_HostSentMoreThanLimit       = 2
	FC_HostDidNotResumeSending     = 3
	FC_NotEnoughDataAvailable      = 4
	FC_RespectedLimitsButNoBlocked = 5
)

type FlowControlScenario struct {
	AbstractScenario
}
func NewFlowControlScenario() *FlowControlScenario {
	return &FlowControlScenario{AbstractScenario{"flow_control", 1, false}}
}
func (s *FlowControlScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	conn.TLSTPHandler.MaxStreamData = 80

	if err := CompleteHandshake(conn); err != nil {
		trace.ErrorCode = FC_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	conn.SendHTTPGETRequest("/index.html", 2)

	var shouldResume bool
	var isBlocked bool

	for {
		packet, err, _ := conn.ReadNextPacket()
		if shouldResume {
			// TODO
		}
		if err != nil {
			readOffset := conn.Streams[4].ReadOffset
			if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) && !isBlocked {
				trace.ErrorCode = FC_RespectedLimitsButNoBlocked
			} else if shouldResume && readOffset == uint64(conn.TLSTPHandler.MaxStreamData) / 2 {
				trace.ErrorCode = FC_HostDidNotResumeSending
			} else if readOffset < uint64(conn.TLSTPHandler.MaxStreamData) {
				trace.ErrorCode = FC_NotEnoughDataAvailable
			}
			trace.Results["error"] = err.Error()
			return
		}

		if conn.Streams[4].ReadOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
			trace.ErrorCode = FC_HostSentMoreThanLimit
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := packet.(*m.ProtectedPacket); ok {
			for _, frame := range pp.Frames {
				_, isGloballyBlocked := frame.(*m.BlockedFrame)
				_, isStreamBlocked := frame.(*m.StreamBlockedFrame)
				isBlocked = isGloballyBlocked || isStreamBlocked
				if isBlocked {
					break
				}
			}
			if isBlocked && !shouldResume {
				maxData := m.MaxDataFrame{uint64(conn.TLSTPHandler.MaxData * 2)}
				conn.TLSTPHandler.MaxData *= 2
				maxStreamData := m.MaxStreamDataFrame{4,uint64(conn.TLSTPHandler.MaxStreamData * 2)}
				conn.TLSTPHandler.MaxStreamData *= 2
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, maxData, maxStreamData)
				conn.SendProtectedPacket(protectedPacket)
				shouldResume = true
			}
		}
	}

	conn.CloseConnection(false, 42, "")
}
