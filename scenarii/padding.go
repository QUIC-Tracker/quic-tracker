package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
)

const (
	P_VNDidNotComplete = 1
	P_ReceivedSmth     = 2
)

type PaddingScenario struct {
	AbstractScenario
}

func NewPaddingScenario() *PaddingScenario {
	return &PaddingScenario{AbstractScenario{name: "padding", version: 1}}
}
func (s *PaddingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	defer connAgents.StopAll()

	sendEmptyInitialPacket := func() {
		var initialLength int
		if conn.UseIPv6 {
			initialLength = qt.MinimumInitialLengthv6
		} else {
			initialLength = qt.MinimumInitialLength
		}

		initialPacket := qt.NewInitialPacket(conn)
		payloadLen := len(initialPacket.EncodePayload())
		paddingLength := initialLength - (len(initialPacket.Header().Encode()) + int(VarIntLen(uint64(payloadLen))) + payloadLen + conn.CryptoState(qt.EncryptionLevelInitial).Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			initialPacket.Frames = append(initialPacket.Frames, new(qt.PaddingFrame))
		}

		conn.DoSendPacket(initialPacket, qt.EncryptionLevelInitial)
	}

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	sendEmptyInitialPacket()

	select {
	case i := <-incPackets:
		packet := i.(qt.Packet)
		if vn, ok := packet.(*qt.VersionNegotiationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err != nil {
				trace.MarkError(P_VNDidNotComplete, err.Error(), vn)
				return
			}
			sendEmptyInitialPacket()
		} else {
			trace.MarkError(P_ReceivedSmth, "", packet)
			s.Finished()
		}
	case <-conn.ConnectionClosed:
		return
	case <-s.Timeout():
		return
	}
}
