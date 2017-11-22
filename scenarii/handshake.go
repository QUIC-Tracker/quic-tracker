package scenarii

import (
	m "masterthesis"
	"fmt"
	"github.com/bifurcation/mint"
	"crypto"
	"strings"
)

type HandshakeScenario struct {
	AbstractScenario
}

func NewHandshakeScenario() *HandshakeScenario {
	return &HandshakeScenario{AbstractScenario{"handshake", 1}}
}
func (s *HandshakeScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.SendClientInitialPacket()

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			println(err)
			return
		}
		if scp, ok := packet.(*m.ServerCleartextPacket); ok {
			ongoingHandhake = conn.ProcessServerHello(scp)
			println(trace.Host, "ok!")
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			var version uint32
			for _, v := range vn.SupportedVersions {
				if v >= 0xff000006 && v <= 0xff000007 {
					version = uint32(v)
				}
			}
			fmt.Printf("%s: switching to version %#x\n", trace.Host, version)
			if version == 0xff000007 {
				conn := m.NewConnection(trace.Host, strings.Split(trace.Host, ":")[0])
				conn.Version = version
				params := mint.CipherSuiteParams{  // See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.3
					Suite:  mint.TLS_AES_128_GCM_SHA256,
					Cipher: nil,
					Hash:   crypto.SHA256,
					KeyLen: 16,
					IvLen:  12,
				}
				conn.Cleartext = m.NewCleartextSaltedCryptoState(conn, &params)
				s.Run(conn, trace)
			} else {
				conn.Version = version
				s.Run(conn, trace)
			}
		}
	}
}
