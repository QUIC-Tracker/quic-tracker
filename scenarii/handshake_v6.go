package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

)

type Handshakev6Scenario struct {
	AbstractScenario
}

func NewHandshakev6Scenario() *Handshakev6Scenario {
	return &Handshakev6Scenario{AbstractScenario{name: "handshake_v6", version: 2, ipv6: true}}
}
func (s *Handshakev6Scenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	NewHandshakeScenario().Run(conn, trace, preferredPath, debug)
}
