package scenario

import (
	m "masterthesis"
	"strings"
)

const (
	NotAnsweringToVN = 1
	DidNotEchoVersion = 2
	Timeout = 3
)

const ForceVersionNegotiation = 0x1a2a3a4a

func RunVersionNegotiationScenario(host string, trace *m.Trace) string {
	trace.Scenario = "version_negotation"
	trace.ScenarioVersion = 1

	conn := m.NewConnection(host, strings.Split(host, ":")[0])
	conn.Version = ForceVersionNegotiation
	conn.SendClientInitialPacket()
	packet, err := conn.ReadNextPacket()

	// TODO: Try to determine the two last announced versions make up an AEAD hash instead of being legitimate version

	if err != nil {
		trace.ErrorCode = Timeout
	} else {
		if packet.Header().PacketType() != m.VersionNegotiation {
			trace.ErrorCode = NotAnsweringToVN
			trace.Results["received_packet_type"] = packet.Header().PacketType()
		} else {
			packet, _ := packet.(*m.VersionNegotationPacket)
			trace.Results["supported_versions"] = packet.SupportedVersions

			echoed_version := packet.Header().(*m.LongHeader).Version
			if echoed_version != conn.Version {
				trace.ErrorCode = DidNotEchoVersion
				trace.Results["echoed_version"] = echoed_version
			}
		}
	}

	return strings.Split(conn.ConnectedIp().String(), ":")[0]
}
