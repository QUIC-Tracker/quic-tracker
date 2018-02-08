package scenarii

import (
	m "masterthesis"
)

const (
	VN_NotAnsweringToVN               = 1
	VN_DidNotEchoVersion              = 2  // draft-07 and below were stating that VN packets should echo the version of the client. It is not used anymore
	VN_LastTwoVersionsAreActuallySeal = 3  // draft-05 and below used AEAD to seal cleartext packets, VN packets should not be sealed, but some implementations did anyway.
	VN_Timeout                        = 4
)

const ForceVersionNegotiation = 0x1a2a3a4a

type VersionNegotationScenario struct {
	AbstractScenario
}
func NewVersionNegotationScenario() *VersionNegotationScenario {
	return &VersionNegotationScenario{AbstractScenario{"version_negotation", 2}}
}
func (s *VersionNegotationScenario) Run(conn *m.Connection, trace *m.Trace) {
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
