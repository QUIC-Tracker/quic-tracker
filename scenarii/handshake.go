package scenarii

import (
	m "masterthesis"
	"fmt"
	"strings"
	"github.com/davecgh/go-spew/spew"
)

type HandshakeScenario struct {
	AbstractScenario
}

func NewHandshakeScenario() *HandshakeScenario {
	return &HandshakeScenario{AbstractScenario{"handshake", 1}}
}
func (s *HandshakeScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.SendClientInitialPacket()

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
		println(trace.Host, "Reading packet")
		packet, err, _ := conn.ReadNextPacket()
		fmt.Printf("Received %T\n", packet)
		if err != nil {
			println(err.Error())
			return
		}
		if scp, ok := packet.(*m.ServerCleartextPacket); ok {
			ongoingHandshake, err = conn.ProcessServerHello(scp)
			if err == nil && !ongoingHandshake {
				println(trace.Host, "ok!")
				conn.CloseConnection(false, 42, "")
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			var version uint32
			for _, v := range vn.SupportedVersions {
				if v >= 0xff000006 && v <= 0xff000007 {
					version = uint32(v)
				}
			}
			if version == 0 {
				return
			}
			fmt.Printf("%s: switching to version %#x\n", trace.Host, version)
			oldVersion, oldALPN := m.QuicVersion, m.QuicALPNToken
			m.QuicVersion, m.QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
			conn.TransitionTo(strings.Split(trace.Host, ":")[0], version, m.QuicALPNToken)
			s.Run(conn, trace)
			m.QuicVersion, m.QuicALPNToken = oldVersion, oldALPN
			return
		} else {
			spew.Dump(packet)
			return
		}
	}
}
