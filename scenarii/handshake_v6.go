package scenarii

import (
	m "masterthesis"
)

type Handshakev6Scenario struct {
	AbstractScenario
}

func NewHandshakev6Scenario() *Handshakev6Scenario {
	return &Handshakev6Scenario{AbstractScenario{"handshake_v6", 2, true}}
}
func (s *Handshakev6Scenario) Run(conn *m.Connection, trace *m.Trace) {
	NewHandshakeScenario().Run(conn, trace)
}
