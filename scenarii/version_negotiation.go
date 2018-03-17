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
	VN_NotAnsweringToVN               = 1
	VN_DidNotEchoVersion              = 2  // draft-07 and below were stating that VN packets should echo the version of the client. It is not used anymore
	VN_LastTwoVersionsAreActuallySeal = 3  // draft-05 and below used AEAD to seal cleartext packets, VN packets should not be sealed, but some implementations did anyway.
	VN_Timeout                        = 4
)

const ForceVersionNegotiation = 0x1a2a3a4a

type VersionNegotiationScenario struct {
	AbstractScenario
}
func NewVersionNegotiationScenario() *VersionNegotiationScenario {
	return &VersionNegotiationScenario{AbstractScenario{"version_negotiation", 2, false}}
}
func (s *VersionNegotiationScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	conn.Version = ForceVersionNegotiation
	conn.SendInitialPacket()
	packet, err, _ := conn.ReadNextPacket()

	if err != nil {
		trace.ErrorCode = VN_Timeout
	} else {
		if _, isVN := packet.(m.VersionNegotationPacket); isVN {
			trace.ErrorCode = VN_NotAnsweringToVN
			trace.Results["received_packet_type"] = packet.Header().PacketType()
		} else {
			packet, _ := packet.(*m.VersionNegotationPacket)
			trace.Results["supported_versions"] = packet.SupportedVersions
		}
	}
}
