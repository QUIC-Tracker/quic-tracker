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

	"time"
)

const (
	SSRS_TLSHandshakeFailed               = 1
	SSRS_DidNotCloseTheConnection         = 2
	SSRS_CloseTheConnectionWithWrongError = 3
	SSRS_MaxStreamUniTooLow               = 4
	SSRS_UnknownError                     = 5
)

type StopSendingOnReceiveStreamScenario struct {
	AbstractScenario
}

func NewStopSendingOnReceiveStreamScenario() *StopSendingOnReceiveStreamScenario {
	return &StopSendingOnReceiveStreamScenario{AbstractScenario{"stop_sending_frame_on_receive_stream", 1, false, nil}}
}

func (s *StopSendingOnReceiveStreamScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, SSRS_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams == 0 {
		trace.MarkError(SSRS_MaxStreamUniTooLow, "", nil)
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)
	conn.FrameQueue.Submit(m.QueuedFrame{&m.StopSendingFrame{2, 0}, m.EncryptionLevel1RTT})

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	trace.ErrorCode = SSRS_DidNotCloseTheConnection
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case m.Framer:
				if p.Contains(m.ConnectionCloseType) {
					cc := p.GetFirst(m.ConnectionCloseType).(*m.ConnectionCloseFrame)
					if cc.ErrorCode != m.ERR_PROTOCOL_VIOLATION {
						trace.MarkError(SSRS_CloseTheConnectionWithWrongError, "", p)
						trace.Results["connection_closed_error_code"] = fmt.Sprintf("0x%x", cc.ErrorCode)
						return
					}
					trace.ErrorCode = 0
					return
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
