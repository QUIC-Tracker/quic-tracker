package scenarii

import (
	m "masterthesis"
	"encoding/binary"
	"bytes"
)

const (
	VN_NotAnsweringToVN               = 1
	VN_DidNotEchoVersion              = 2
	VN_LastTwoVersionsAreActuallySeal = 3
	VN_Timeout                        = 4
)

const ForceVersionNegotiation = 0x1a2a3a4a

type VersionNegotationScenario struct {
	AbstractScenario
}
func NewVersionNegotationScenario() *VersionNegotationScenario {
	return &VersionNegotationScenario{AbstractScenario{"version_negotation", 1}}
}
func (s *VersionNegotationScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.Version = ForceVersionNegotiation
	conn.SendClientInitialPacket()
	packet, err, buf := conn.ReadNextPacket()

	if err != nil {
		trace.ErrorCode = VN_Timeout
	} else {
		if packet.Header().PacketType() != m.VersionNegotiation {
			trace.ErrorCode = VN_NotAnsweringToVN
			trace.Results["received_packet_type"] = packet.Header().PacketType()
		} else {
			packet, _ := packet.(*m.VersionNegotationPacket)
			trace.Results["supported_versions"] = packet.SupportedVersions

			nVersions := len(packet.SupportedVersions)
			if nVersions > 1 {
				v1, v2 := packet.SupportedVersions[nVersions-2], packet.SupportedVersions[nVersions-1]
				hash := bytes.NewBuffer(make([]byte, 0, 8))
				binary.Write(hash, binary.BigEndian, v1)
				binary.Write(hash, binary.BigEndian, v2)

				_, err := m.NewCleartextCryptoState().Read.Open(nil, m.EncodeArgs(packet.Header().PacketNumber()), buf[m.LongHeaderSize:], buf[:m.LongHeaderSize])
				if err == nil {
					trace.ErrorCode = VN_LastTwoVersionsAreActuallySeal
				}
			}

			echoed_version := packet.Header().(*m.LongHeader).Version
			if echoed_version != conn.Version {
				trace.ErrorCode = VN_DidNotEchoVersion
				trace.Results["echoed_version"] = echoed_version
			}
		}
	}
}
