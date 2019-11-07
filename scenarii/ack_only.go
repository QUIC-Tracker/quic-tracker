package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
)

const (
	AO_TLSHandshakeFailed   = 1
	AO_SentAOInResponseOfAO = 2
)

type AckOnlyScenario struct {
	AbstractScenario
}

func NewAckOnlyScenario() *AckOnlyScenario {
	return &AckOnlyScenario{AbstractScenario{name: "ack_only", version: 1}}
}
func (s *AckOnlyScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, AO_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")
	connAgents.Stop("AckAgent")

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)

	var ackOnlyPackets []qt.PacketNumber

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if p.PNSpace() != qt.PNSpaceNoSpace {
				conn.AckQueue[p.PNSpace()] = append(conn.AckQueue[p.PNSpace()], p.Header().PacketNumber())
			}
			if p.ShouldBeAcknowledged() {
				ackFrame := conn.GetAckFrame(p.PNSpace())
				if ackFrame == nil {
					break
				}
				var packet qt.Framer
				switch p.PNSpace() {
				case qt.PNSpaceInitial:
					packet = qt.NewInitialPacket(conn)
				case qt.PNSpaceHandshake:
					packet = qt.NewHandshakePacket(conn)
				case qt.PNSpaceAppData:
					packet = qt.NewProtectedPacket(conn)
				}

				packet.AddFrame(ackFrame)
				conn.DoSendPacket(packet, packet.EncryptionLevel())
				if p.PNSpace() == qt.PNSpaceAppData {
					ackOnlyPackets = append(ackOnlyPackets, packet.Header().PacketNumber())
				}
			} else if packet, ok := p.(*qt.ProtectedPacket); ok && packet.Contains(qt.AckType) {
				ack := packet.GetFirst(qt.AckType).(*qt.AckFrame)
				if containsAll(ack.GetAckedPackets(), ackOnlyPackets) {
					trace.MarkError(AO_SentAOInResponseOfAO, "", p)
					return
				}
			}
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}

func containsAll(a []qt.PacketNumber, b []qt.PacketNumber) bool { // Checks a \in b
	for _, i := range a {
		contains := false
		for _, j := range b {
			if i == j {
				contains = true
				break
			}
		}
		if !contains {
			return false
		}
	}
	return true
}
