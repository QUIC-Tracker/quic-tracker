package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"time"
)

type PingScenario struct {
	AbstractScenario
}

func NewPingScenario() *PingScenario {
	return &PingScenario{
		AbstractScenario{
			name:    "ping", // The name must match the scenario filename
			version: 1,      // This value is echoed in the test results traces
			ipv6:    false,  // Forces the test to execute over IPv6
			timeout: nil,
		},
	}
}

const (
	P_TLSHandshakeFailed = 1 // The handshake did not complete
	P_NoACKReceived      = 2 // No ACK was received
)

func (s *PingScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, P_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	pp := qt.NewProtectedPacket(conn)
	pp.AddFrame(new(qt.PingFrame))
	conn.SendPacket(pp, qt.EncryptionLevel1RTT)

	pings := []qt.PacketNumber{pp.Header().PacketNumber()}
	pingRetransmit := time.NewTicker(500 * time.Millisecond)

	for {
		select {
		case i := <-incomingPackets:
			switch p := i.(type) {
			case *qt.ProtectedPacket:
				for _, f := range p.GetAll(qt.AckType) {
					for _, pn := range f.(*qt.AckFrame).GetAckedPackets() {
						for _, ping := range pings {
							if pn == ping {
								trace.ErrorCode = 0
								return
							}
						}
					}
				}
			}
		case <-pingRetransmit.C:
			pp := qt.NewProtectedPacket(conn)
			pp.AddFrame(new(qt.PingFrame))
			conn.SendPacket(pp, qt.EncryptionLevel1RTT)
			pings = append(pings, pp.Header().PacketNumber())
		case <-s.Timeout().C:
			trace.ErrorCode = P_NoACKReceived
			return
		}
	}
}
