package scenarii

import (
	m "masterthesis"
	"github.com/davecgh/go-spew/spew"
	"errors"
)

type Scenario interface {
	Name() string
	Version() int
	IPv6() bool
	Run(conn *m.Connection, trace *m.Trace)
}

type AbstractScenario struct {
	name    string
	version int
	ipv6    bool
}
func (s *AbstractScenario) Name() string {
	return s.name
}
func (s *AbstractScenario) Version() int {
	return s.version
}
func (s *AbstractScenario) IPv6() bool {
	return s.ipv6
}

func CompleteHandshake(conn *m.Connection) error {
	conn.SendInitialPacket()

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			return err
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, err = conn.ProcessServerHello(scp)
			if err != nil {
				return err
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			conn.ProcessVersionNegotation(vn)
			conn.SendInitialPacket()
		} else {
			defer spew.Dump(packet)
			return errors.New("Received incorrect packet type during handshake")
		}
	}

	return nil
}