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
	conn.RetransmissionTicker.Stop()

	sendEmptyInitialPacket := func() {
		var initialLength int
		if conn.UseIPv6 {
			initialLength = m.MinimumInitialLengthv6
		} else {
			initialLength = m.MinimumInitialLength
		}

		initialPacket := m.NewInitialPacket(conn)

		paddingLength := initialLength - (initialPacket.Header().Length() + len(initialPacket.EncodePayload()) + conn.CryptoStates[m.EncryptionLevelInitial].Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			initialPacket.Frames = append(initialPacket.Frames, new(m.PaddingFrame))
		}

		conn.SendPacket(initialPacket, m.EncryptionLevelInitial)
	}

	sendEmptyInitialPacket()

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	packet := (<-incPackets).(m.Packet)

	if vn, ok := packet.(*m.VersionNegotationPacket); ok {
		if err := conn.ProcessVersionNegotation(vn); err != nil {
			trace.MarkError(P_VNDidNotComplete, err.Error(), vn)
			return
		}
		sendEmptyInitialPacket()
	} else {
		trace.MarkError(P_ReceivedSmth, "", packet)
	}
}
