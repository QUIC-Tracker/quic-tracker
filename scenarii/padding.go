package scenarii

import (
	m "github.com/mpiraux/master-thesis"
)

const (
	P_VNDidNotComplete = 1
	P_ReceivedSmth	   = 2
)

type PaddingScenario struct {
	AbstractScenario
}

func NewPaddingScenario() *PaddingScenario {
	return &PaddingScenario{AbstractScenario{"padding", 1, false}}
}
func (s *PaddingScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	sendEmptyInitialPacket := func() {
		var initialLength int
		if conn.UseIPv6 {
			initialLength = m.MinimumInitialLengthv6
		} else {
			initialLength = m.MinimumInitialLength
		}

		initialPacket := m.NewInitialPacket(conn)

		paddingLength := initialLength - (m.LongHeaderSize + len(initialPacket.EncodePayload()) + conn.Cleartext.Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			initialPacket.Frames = append(initialPacket.Frames, new(m.PaddingFrame))
		}

		conn.SendHandshakeProtectedPacket(initialPacket)
	}

	sendEmptyInitialPacket()
	packet, err, _ := conn.ReadNextPacket()

	if vn, ok := packet.(*m.VersionNegotationPacket); packet != nil && ok {
		if err := conn.ProcessVersionNegotation(vn); err != nil {
			trace.MarkError(P_VNDidNotComplete, err.Error())
			return
		}
		sendEmptyInitialPacket()
	}

	for {
		if err != nil {
			trace.Results["error"] = err.Error()
			break
		} else if _, ok := packet.(*m.VersionNegotationPacket); packet != nil && !ok {  // TODO: Distinguish ACKs from other packets, see https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-9.1
			trace.MarkError(P_ReceivedSmth, "")
			break
		}

		packet, err, _ = conn.ReadNextPacket()
	}
}
