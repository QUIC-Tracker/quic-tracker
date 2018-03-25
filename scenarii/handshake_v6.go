/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package scenarii

import (
	m "github.com/mpiraux/master-thesis"
)

type Handshakev6Scenario struct {
	AbstractScenario
}

func NewHandshakev6Scenario() *Handshakev6Scenario {
	return &Handshakev6Scenario{AbstractScenario{"handshake_v6", 2, true}}
}
func (s *Handshakev6Scenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	NewHandshakeScenario().Run(conn, trace, preferredUrl, debug)
}
