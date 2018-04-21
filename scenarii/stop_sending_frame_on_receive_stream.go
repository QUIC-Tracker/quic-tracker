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
	SSRS_TLSHandshakeFailed               = 1
	SSRS_DidNotCloseTheConnection         = 2
	SSRS_CloseTheConnectionWithWrongError = 3
	SSRS_MaxStreamUniTooLow				  = 4
	SSRS_UnknownError					  = 5
)

type StopSendingOnReceiveStreamScenario struct {
	AbstractScenario
}

func NewStopSendingOnReceiveStreamScenario() *StopSendingOnReceiveStreamScenario {
	return &StopSendingOnReceiveStreamScenario{AbstractScenario{"stop_sending_frame_on_receive_stream", 1, false}}
}

func (s *StopSendingOnReceiveStreamScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	packets, err := CompleteHandshake(conn)
	if err != nil {
		trace.MarkError(SSRS_TLSHandshakeFailed, err.Error())
		return
	}

	if conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni < 2 {
		trace.MarkError(SSRS_MaxStreamUniTooLow, "")
		trace.Results["expected_max_stream_uni"] = ">= 2"
		trace.Results["received_max_stream_uni"] = conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni
		return
	}

	conn.SendHTTPGETRequest(preferredUrl, 2)

	stopSendingFrame := m.StopSendingFrame{StreamId: 2, ErrorCode: 42}

	pp := m.NewProtectedPacket(conn)
	pp.Frames = append(pp.Frames, stopSendingFrame)
	conn.SendProtectedPacket(pp)

	for i := 0; i < 30; i++ {
		if i >= 0 || packets == nil {
			packets, err, _ = conn.ReadNextPackets()
		}
		if err != nil {
			switch e := err.(type) {
			case *net.OpError:
				// the peer timed out without closing the connection
				if e.Timeout() {
					trace.ErrorCode = SSRS_DidNotCloseTheConnection
				} else {
					trace.ErrorCode = SSRS_UnknownError
				}
				trace.Results["error"] = e.Error()
			}
			return
		}

		for _, packet := range packets {
			if packet.ShouldBeAcknowledged() {
				protectedPacket := m.NewProtectedPacket(conn)
				protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(protectedPacket)
			}

			switch ppReadPacket := packet.(type) {
			case *m.ProtectedPacket:
				for _, f := range ppReadPacket.Frames {
					switch f2 := f.(type) {
					case *m.ConnectionCloseFrame:
						if f2.ErrorCode != m.ERR_PROTOCOL_VIOLATION {
							trace.MarkError(SSRS_CloseTheConnectionWithWrongError, "")
							trace.Results["connection_closed_error_code"] = fmt.Sprintf("0x%x", f2.ErrorCode)
							return
						}
						trace.ErrorCode = 0
						return
					default:
					}
				}
			default:
				// TODO: Detect spurious retransmissions
				// handshake packet: should not happen here
				// trace.Results["received_unexpected_packet_type"] = fmt.Sprintf("0x%x (%T)", packet.Header().PacketType(), packet)
			}
		}

	}
	trace.ErrorCode = SSRS_DidNotCloseTheConnection
}
