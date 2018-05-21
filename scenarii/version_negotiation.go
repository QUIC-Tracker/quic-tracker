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
	VN_UnusedFieldIsIdentical		  = 5  // See https://github.com/quicwg/base-drafts/issues/963
)

const ForceVersionNegotiation = 0x1a2a3a4a

type VersionNegotiationScenario struct {
	AbstractScenario
}
func NewVersionNegotiationScenario() *VersionNegotiationScenario {
	return &VersionNegotiationScenario{AbstractScenario{"version_negotiation", 2, false}}
}
func (s *VersionNegotiationScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	handlePacket := func (packet m.Packet, err error) *m.VersionNegotationPacket {
		if err != nil {
			trace.ErrorCode = VN_Timeout
			return nil
		} else {
			if _, isVN := packet.(*m.VersionNegotationPacket); !isVN {
				trace.MarkError(VN_NotAnsweringToVN, "")
				trace.Results["received_packet_type"] = packet.Header().PacketType()
				return nil
			} else {
				packet, _ := packet.(*m.VersionNegotationPacket)
				trace.Results["supported_versions"] = packet.SupportedVersions
				return packet
			}
		}
	}

	conn.RetransmissionTicker.Stop()
	conn.Version = ForceVersionNegotiation
	initial := conn.GetInitialPacket()
	conn.SendHandshakeProtectedPacket(initial)
	packets, err, _ := conn.ReadNextPackets()

	for _, packet := range packets {
		vn1 := handlePacket(packet, err)
		if vn1 != nil {
			conn.SendHandshakeProtectedPacket(initial)
			packets, err, _ = conn.ReadNextPackets()
			for _, packet := range packets {
				vn2 := handlePacket(packet, err)
				if vn2 != nil && vn1.UnusedField == vn2.UnusedField {
					trace.ErrorCode = VN_UnusedFieldIsIdentical  // Assume true until proven otherwise
					conn.SendHandshakeProtectedPacket(initial)
					packets, err, _ = conn.ReadNextPackets()
					for _, packet := range packets {
						vn3 := handlePacket(packet, err)
						if vn3 != nil && vn3.UnusedField != vn2.UnusedField {
							trace.ErrorCode = 0
						}
					}
				}
			}
		}
	}
}
