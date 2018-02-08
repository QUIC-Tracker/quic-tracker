package scenarii

import (
	m "masterthesis"
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
func (s *HandshakeScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.SendInitialPacket()

	ongoingHandshake := true
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				println(err.Error())
			}
		}
		ongoingHandshake = false
	}()

	for ongoingHandshake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			trace.ErrorCode = H_Timeout
			return
		}
		if handshake, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandshake, err = conn.ProcessServerHello(handshake)
			if err == nil && !ongoingHandshake {
				trace.Results["negotiated_version"] = conn.Version
				conn.CloseConnection(false, 42, "")
			} else if err != nil {
				trace.ErrorCode = H_TLSHandshakeFailed
				trace.Results["tls_error"] = err.Error()
				conn.CloseStream(0)
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			var version uint32
			for _, v := range vn.SupportedVersions {
				if v >= m.MinimumVersion && v <= m.MaximumVersion {
					version = uint32(v)
				}
			}
			if version == 0 {
				trace.ErrorCode = H_NoCompatibleVersionAvailable
				trace.Results["supported_versions"] = vn.SupportedVersions
				return
			}
			oldVersion, oldALPN := m.QuicVersion, m.QuicALPNToken
			m.QuicVersion, m.QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
			conn.TransitionTo(version, m.QuicALPNToken)
			s.Run(conn, trace)
			m.QuicVersion, m.QuicALPNToken = oldVersion, oldALPN
			return
		} else {
			trace.ErrorCode = H_ReceivedUnexpectedPacketType
			trace.Results["unexpected_packet_type"] = packet.Header().PacketType()
			return
		}
	}
}
