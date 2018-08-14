package scenarii

import (
	m "github.com/mpiraux/master-thesis"
	. "github.com/mpiraux/master-thesis/lib"
	"time"
	"github.com/mpiraux/master-thesis/agents"
)

const (
	P_VNDidNotComplete = 1
	P_ReceivedSmth     = 2
)

type PaddingScenario struct {
	AbstractScenario
}

func NewPaddingScenario() *PaddingScenario {
	return &PaddingScenario{AbstractScenario{"padding", 1, false, nil}}
}
func (s *PaddingScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	defer connAgents.StopAll()

	sendEmptyInitialPacket := func() {
		var initialLength int
		if conn.UseIPv6 {
			initialLength = m.MinimumInitialLengthv6
		} else {
			initialLength = m.MinimumInitialLength
		}

		initialPacket := m.NewInitialPacket(conn)
		payloadLen := len(initialPacket.EncodePayload())
		paddingLength := initialLength - (len(initialPacket.Header().Encode()) + int(VarIntLen(uint64(payloadLen))) + payloadLen + conn.CryptoStates[m.EncryptionLevelInitial].Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			initialPacket.Frames = append(initialPacket.Frames, new(m.PaddingFrame))
		}

		conn.SendPacket(initialPacket, m.EncryptionLevelInitial)
	}

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	sendEmptyInitialPacket()

	select {
	case i := <-incPackets:
		packet := i.(m.Packet)
		if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err != nil {
				trace.MarkError(P_VNDidNotComplete, err.Error(), vn)
				return
			}
			sendEmptyInitialPacket()
		} else {
			trace.MarkError(P_ReceivedSmth, "", packet)
		}
	case <-s.Timeout().C:
		return
	}
}
