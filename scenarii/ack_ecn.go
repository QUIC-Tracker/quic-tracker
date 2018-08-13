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
	"time"
	m "github.com/mpiraux/master-thesis"
	"github.com/mpiraux/master-thesis/agents"
)

const (
	AE_TLSHandshakeFailed = 1
	AE_FailedToSetECN     = 2
	AE_NonECN             = 3
	AE_NoACKECNReceived   = 4
	AE_NonECNButACKECN    = 5
)

type AckECNScenario struct {
	AbstractScenario
}

func NewAckECNScenario() *AckECNScenario {
	return &AckECNScenario{AbstractScenario{"ack_ecn", 1, false, nil}}
}
func (s *AckECNScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, AE_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	socketAgent := connAgents.Get("SocketAgent").(*agents.SocketAgent)
	ecnStatus := make(chan interface{}, 1000)
	socketAgent.ECNStatus.Register(ecnStatus)

	err := socketAgent.ConfigureECN()
	if err != nil {
		trace.MarkError(AE_FailedToSetECN, err.Error(), nil)
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 0)

	trace.ErrorCode = AE_NonECN
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case m.Framer:
				if p.Contains(m.AckECNType) {
					if trace.ErrorCode == AE_NonECN {
						trace.ErrorCode = AE_NonECNButACKECN
					} else if trace.ErrorCode == AE_NoACKECNReceived {
						trace.ErrorCode = 0
					}
				}
			}
		case i := <-ecnStatus:
			switch i.(agents.ECNStatus) {
			case agents.ECNStatusNonECT:
			case agents.ECNStatusECT_0, agents.ECNStatusECT_1, agents.ECNStatusCE:
				if trace.ErrorCode == AE_NonECN {
					trace.ErrorCode = AE_NoACKECNReceived
				} else if trace.ErrorCode == AE_NonECNButACKECN {
					trace.ErrorCode = 0
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
