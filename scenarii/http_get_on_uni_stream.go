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
	"fmt"
)

const (
	GS2_TLSHandshakeFailed                    = 1
	GS2_TooLowStreamIdUniToSendRequest        = 2
	GS2_ReceivedDataOnStream2                 = 3
	GS2_ReceivedDataOnUnauthorizedStream      = 4
	GS2_AnswersToARequestOnAForbiddenStreamID = 5
	GS2_DidNotCloseTheConnection              = 6
)

type GetOnStream2Scenario struct {
	AbstractScenario
}

func NewGetOnStream2Scenario() *GetOnStream2Scenario {
	return &GetOnStream2Scenario{AbstractScenario{"http_get_on_uni_stream", 1, false}}
}

func (s *GetOnStream2Scenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	conn.Streams[3] = new(m.Stream)

	conn.TLSTPHandler.MaxStreamIdBidi = 1
	conn.TLSTPHandler.MaxStreamIdUni = 1
	if _, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(GS2_TLSHandshakeFailed, err.Error())
		return
	}

	if conn.TLSTPHandler.ReceivedParameters != nil {
		trace.Results["received_transport_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON
	} else {
		trace.MarkError(GS2_TLSHandshakeFailed, "no transport parameters received")
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)

outerLoop:
	for i := 0 ; i < 50 ; i++ {
		packets, err, _ := conn.ReadNextPackets()
		if err != nil {
			switch e := err.(type) {
			case *net.OpError:
				// the peer timed out without closing the connection
				if e.Timeout() && conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni < 1 {
					trace.ErrorCode = GS2_DidNotCloseTheConnection
					trace.Results["error"] = fmt.Sprintf("the peer did not close the connection after waiting %d seconds", conn.TLSTPHandler.ReceivedParameters.IdleTimeout)
				}
			default:
				trace.Results["error"] = err.Error()
			}
			return
		}

		for _, packet := range packets {
			switch pp := packet.(type) {
			case *m.ProtectedPacket:
				for _, f := range pp.Frames {
					switch f2 := f.(type) {
					case *m.StreamFrame:
						if f2.StreamId == 2 {
							trace.MarkError(GS2_ReceivedDataOnStream2, "")
							break outerLoop
						} else if f2.StreamId > 3 {
							trace.MarkError(GS2_ReceivedDataOnUnauthorizedStream, "")
						} else if f2.StreamId == 3 && conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni < 1 {
							// they answered us even if we sent a get request on a Stream ID above their initial_max_stream_id_uni
							// trace.MarkError(GS2_AnswersToARequestOnAForbiddenStreamID, "")
							// Let's be more liberal about this case until the HTTP mapping is adopted in an implementation draft
						}
					case *m.ConnectionCloseFrame:
						if trace.ErrorCode == GS2_TooLowStreamIdUniToSendRequest {
							trace.ErrorCode = 0
						}
						break outerLoop
					}
				}
				if pp.ShouldBeAcknowledged() {
					toSend := m.NewProtectedPacket(conn)
					toSend.Frames = append(toSend.Frames, conn.GetAckFrame())
					conn.SendProtectedPacket(toSend)
				}

			default:
				toSend := m.NewHandshakePacket(conn)
				toSend.Frames = append(toSend.Frames, conn.GetAckFrame())
				conn.SendHandshakeProtectedPacket(toSend)
			}
		}

	}

	conn.CloseConnection(false, 0, "")
}
