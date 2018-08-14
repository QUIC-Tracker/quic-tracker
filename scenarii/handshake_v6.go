package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

)

type Handshakev6Scenario struct {
	AbstractScenario
}

func NewHandshakev6Scenario() *Handshakev6Scenario {
	return &Handshakev6Scenario{AbstractScenario{"handshake_v6", 2, true, nil}}
}
func (s *Handshakev6Scenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	NewHandshakeScenario().Run(conn, trace, preferredUrl, debug)
}
