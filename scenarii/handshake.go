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
)

const (
	H_ReceivedUnexpectedPacketType = 1
	H_TLSHandshakeFailed = 2
	H_NoCompatibleVersionAvailable = 3
	H_Timeout = 4
)

type HandshakeScenario struct {
	AbstractScenario
}

func NewHandshakeScenario() *HandshakeScenario {
	return &HandshakeScenario{AbstractScenario{"handshake", 2, false}}
}
func (s *HandshakeScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	ongoingHandshake := true
	var err error
	for p := range conn.IncomingPackets {
		if !ongoingHandshake {
			break
		}
		switch p := p.(type) {
		case *m.HandshakePacket, *m.RetryPacket:
			var response m.Packet
			ongoingHandshake, response, err = conn.ProcessServerHello(p.(m.Framer))
			if err == nil && !ongoingHandshake {
				trace.Results["negotiated_version"] = conn.Version
				conn.CloseConnection(false, 42, "")
			} else if err != nil {
				trace.MarkError(H_TLSHandshakeFailed, err.Error(), p)
				conn.CloseConnection(true, 0, "")
			}
			if response != nil {
				conn.SendHandshakeProtectedPacket(response)
			}
		case *m.VersionNegotationPacket:
			var version uint32
			for _, v := range p.SupportedVersions {
				if v >= m.MinimumVersion && v <= m.MaximumVersion {
					version = uint32(v)
				}
			}
			if version == 0 {
				trace.MarkError(H_NoCompatibleVersionAvailable, "", p)
				trace.Results["supported_versions"] = p.SupportedVersions
				return
			}
			oldVersion, oldALPN := m.QuicVersion, m.QuicALPNToken
			m.QuicVersion, m.QuicALPNToken = version, fmt.Sprintf("hq-%02d", version&0xff)
			conn.TransitionTo(version, m.QuicALPNToken, nil)
			s.Run(conn, trace, preferredUrl, debug)
			m.QuicVersion, m.QuicALPNToken = oldVersion, oldALPN
			return
		default:
			trace.MarkError(H_ReceivedUnexpectedPacketType, "", p)
			trace.Results["unexpected_packet_type"] = p.Header().PacketType()
			return
		}
	}
	if ongoingHandshake {
		trace.ErrorCode = H_TLSHandshakeFailed
	}
}
