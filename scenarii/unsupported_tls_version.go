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
	UTS_NoConnectionCloseSent        = 1
	UTS_WrongErrorCodeIsUsed         = 2 // See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-11
	UTS_VNDidNotComplete             = 3
	UTS_ReceivedUnexpectedPacketType = 4
)

type UnsupportedTLSVersionScenario struct {
	AbstractScenario
}

func NewUnsupportedTLSVersionScenario() *UnsupportedTLSVersionScenario {
	return &UnsupportedTLSVersionScenario{AbstractScenario{"unsupported_tls_version", 1, false}}
}
func (s *UnsupportedTLSVersionScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	sendUnsupportedInitial(conn)

	var connectionClosed bool
	for {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			trace.Results["error"] = err.Error()
			break
		}

		if packet.ShouldBeAcknowledged() {
			handshakePacket := m.NewHandshakePacket(conn)
			handshakePacket.Frames = append(handshakePacket.Frames, conn.GetAckFrame())
			conn.SendHandshakeProtectedPacket(handshakePacket)
		}

		if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err != nil {
				trace.MarkError(UTS_VNDidNotComplete, err.Error())
				return
			}
			sendUnsupportedInitial(conn)
		} else if fPacket, ok := packet.(m.Framer); ok {
			for _, frame := range fPacket.GetFrames() {
				if cc, ok := frame.(*m.ConnectionCloseFrame); ok { // See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-11
					if cc.ErrorCode != 0x201 {
						trace.MarkError(UTS_WrongErrorCodeIsUsed, "")
					}
					trace.Results["connection_reason_phrase"] = cc.ReasonPhrase
					connectionClosed = true
				}
			}
		} else {
			trace.MarkError(UTS_ReceivedUnexpectedPacketType, "")
		}
	}

	if !connectionClosed {
		trace.ErrorCode = UTS_NoConnectionCloseSent
	}

}

func sendUnsupportedInitial(conn *m.Connection) {
	initialPacket := conn.GetInitialPacket()
	initialPacket.Frames[0].(*m.StreamFrame).StreamData[60] = 0x00 // Advertise support of TLS 1.3 draft-00
	conn.SendHandshakeProtectedPacket(initialPacket)
}
