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
	GS2_TLSHandshakeFailed                    = 1
	GS2_TooLowStreamIdUniToSendRequest        = 2
	GS2_ReceivedDataOnStream2                 = 3
	GS2_ReceivedDataOnUnauthorizedStream      = 4
	GS2_AnswersToARequestOnAForbiddenStreamID = 5 // This is hard to disambiguate sometimes, we don't check anymore
	GS2_DidNotCloseTheConnection              = 6
)

type GetOnStream2Scenario struct {
	AbstractScenario
}

func NewGetOnStream2Scenario() *GetOnStream2Scenario {
	return &GetOnStream2Scenario{AbstractScenario{"http_get_on_uni_stream", 1, false, nil}}
}

func (s *GetOnStream2Scenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	conn.TLSTPHandler.MaxBidiStreams = 1
	conn.TLSTPHandler.MaxUniStreams = 1

	connAgents := s.CompleteHandshake(conn, trace, GS2_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	trace.Results["received_transport_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON
	if conn.TLSTPHandler.ReceivedParameters.MaxUniStreams == 0 {
		trace.ErrorCode = GS2_DidNotCloseTheConnection
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)

	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case *m.ProtectedPacket:
				for _, f := range p.Frames {
					switch f := f.(type) {
					case *m.StreamFrame:
						if f.StreamId == 2 {
							trace.MarkError(GS2_ReceivedDataOnStream2, "", p)
							return
						} else if f.StreamId > 3 {
							trace.MarkError(GS2_ReceivedDataOnUnauthorizedStream, "", p)
							return
						}
					case *m.ConnectionCloseFrame:
						if trace.ErrorCode == GS2_DidNotCloseTheConnection && f.ErrorCode == m.ERR_STREAM_ID_ERROR || f.ErrorCode == m.ERR_PROTOCOL_VIOLATION {
							trace.ErrorCode = GS2_TooLowStreamIdUniToSendRequest
						}
						return
					}
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
