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
	"github.com/davecgh/go-spew/spew"
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

func CompleteHandshake(conn *m.Connection) ([]m.Packet, error) {
	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	ongoingHandhake := true
	for ongoingHandhake {
		packets, err, _ := conn.ReadNextPackets()
		if err != nil {
			return nil, err
		}
		for i, packet := range packets {
			if !ongoingHandhake {
				return packets[i:], nil
			}

			spew.Dump(packet)

			switch packet.(type) {
			case *m.HandshakePacket, *m.RetryPacket:
				ongoingHandhake, packet, err = conn.ProcessServerHello(packet.(m.Framer))
				if err != nil {
					return nil, err
				}
				if packet != nil {
					conn.SendHandshakeProtectedPacket(packet)
				}
			case *m.VersionNegotationPacket: {
				err := conn.ProcessVersionNegotation(packet.(*m.VersionNegotationPacket))
				if err != nil {
					return nil, err
				}
				conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
			}
			default:
				if ongoingHandhake {
					return nil, errors.New("Received incorrect packet type during handshake")
				}
			}
		}
	}

	return nil, nil
}