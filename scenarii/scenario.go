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
	"errors"
)

type Scenario interface {
	Name() string
	Version() int
	IPv6() bool
	Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool)
}

type AbstractScenario struct {
	name    string
	version int
	ipv6    bool
}
func (s *AbstractScenario) Name() string {
	return s.name
}
func (s *AbstractScenario) Version() int {
	return s.version
}
func (s *AbstractScenario) IPv6() bool {
	return s.ipv6
}

func CompleteHandshake(conn *m.Connection) (m.Packet, error) {  // Completes the handshake and returns the last packet received
	conn.SendInitialProtectedPacket(conn.GetInitialPacket())

	ongoingHandhake := true
	var err error
	var p m.Packet
	for p = range conn.IncomingPackets {
		switch p.(type) {
		case *m.InitialPacket, *m.HandshakePacket, *m.RetryPacket:
			var response m.Packet
			ongoingHandhake, response, err = conn.ProcessServerHello(p.(m.Framer))
			if err != nil {
				return p, err
			}
			if response != nil {
				switch p.(type) {
				case *m.InitialPacket, *m.RetryPacket:
					conn.SendInitialProtectedPacket(response)
				default:
					conn.SendHandshakeProtectedPacket(response)
				}
			}
		case *m.VersionNegotationPacket:
			err := conn.ProcessVersionNegotation(p.(*m.VersionNegotationPacket))
			if err != nil {
				return p, err
			}
			conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
		default:
			if ongoingHandhake {
				return p, errors.New("received incorrect packet type during handshake")
			}
		}

		if !ongoingHandhake {
			return p, nil
		}
	}

	if ongoingHandhake {
		return p, errors.New("could not complete handshake")
	}

	return p, nil
}