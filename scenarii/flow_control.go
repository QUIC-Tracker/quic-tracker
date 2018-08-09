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
	return &FlowControlScenario{AbstractScenario{"flow_control", 2, false, nil}}
}
func (s *FlowControlScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	conn.TLSTPHandler.MaxStreamData = 80

	connAgents := s.CompleteHandshake(conn, trace, FC_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	conn.SendHTTPGETRequest(preferredUrl, 0)

	var shouldResume bool

forLoop:
	for {
		select {
		case i := <-incPackets:
			p := i.(m.Packet)
			if conn.Streams.Get(4).ReadOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
				trace.MarkError(FC_HostSentMoreThanLimit, "", p)
			}

			if conn.Streams.Get(4).ReadClosed {
				conn.IncomingPackets.Unregister(incPackets)
			}

			readOffset := conn.Streams.Get(4).ReadOffset
			if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) && !shouldResume {
				conn.TLSTPHandler.MaxData *= 2
				conn.TLSTPHandler.MaxStreamData *= 2
				conn.FrameQueue.Submit(m.QueuedFrame{m.MaxDataFrame{uint64(conn.TLSTPHandler.MaxData)}, m.EncryptionLevel1RTT})
				conn.FrameQueue.Submit(m.QueuedFrame{m.MaxStreamDataFrame{4, uint64(conn.TLSTPHandler.MaxStreamData)}, m.EncryptionLevel1RTT})
				shouldResume = true
			}
			case <-s.Timeout().C:
				break forLoop
		}
	}

	readOffset := conn.Streams.Get(4).ReadOffset
	if readOffset == uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = 0
	} else if shouldResume && readOffset == uint64(conn.TLSTPHandler.MaxStreamData)/2 {
		trace.ErrorCode = FC_HostDidNotResumeSending
	} else if readOffset < uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = FC_NotEnoughDataAvailable
	} else if readOffset > uint64(conn.TLSTPHandler.MaxStreamData) {
		trace.ErrorCode = FC_HostSentMoreThanLimit
	}
}
