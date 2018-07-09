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
	FC_RespectedLimitsButNoBlocked = 5  // After discussing w/ the implementers, it is not reasonable to expect a STREAM_BLOCKED or a BLOCKED frame to be sent.
										// These frames should be sent to signal poor window size w.r.t. to the RTT
)

type FlowControlScenario struct {
	AbstractScenario
}
func NewFlowControlScenario() *FlowControlScenario {
	return &FlowControlScenario{AbstractScenario{"flow_control", 2, false}}
}
func (s *FlowControlScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	conn.TLSTPHandler.MaxStreamData = 80

	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(FC_TLSHandshakeFailed, err.Error(), p)
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 4)

	var shouldResume bool

	for p := range conn.IncomingPackets {
		if conn.Streams.Get(4).ReadOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
			trace.MarkError(FC_HostSentMoreThanLimit, "", p)
		}

		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(p.PNSpace()))
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := p.(*m.ProtectedPacket); ok {
			for _, frame := range pp.Frames {
				_, isGloballyBlocked := frame.(*m.BlockedFrame)
				_, isStreamBlocked := frame.(*m.StreamBlockedFrame)
				if isGloballyBlocked || isStreamBlocked {
					break
				}
			}
			if conn.Streams.Get(4).ReadClosed {
				continue
			}

			readOffset := conn.Streams.Get(4).ReadOffset
			if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) && !shouldResume {
				maxData := m.MaxDataFrame{uint64(conn.TLSTPHandler.MaxData * 2)}
				conn.TLSTPHandler.MaxData *= 2
				maxStreamData := m.MaxStreamDataFrame{4, uint64(conn.TLSTPHandler.MaxStreamData * 2)}
				conn.TLSTPHandler.MaxStreamData *= 2
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, maxData, maxStreamData)
				conn.SendProtectedPacket(protectedPacket)
				shouldResume = true
			}
		}
	}

	readOffset := conn.Streams.Get(4).ReadOffset
	if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = 0
	} else if shouldResume && readOffset == uint64(conn.TLSTPHandler.MaxStreamData) / 2 {
		trace.ErrorCode = FC_HostDidNotResumeSending
	} else if readOffset < uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = FC_NotEnoughDataAvailable
	} else if readOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = FC_HostSentMoreThanLimit
	}

	conn.CloseConnection(false, 42, "")
}
