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
	"github.com/davecgh/go-spew/spew"
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

func CompleteHandshake(conn *m.Connection) error {
	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()
		if err != nil {
			return err
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, packet, err = conn.ProcessServerHello(scp)
			if err != nil {
				return err
			}
			if packet != nil {
				conn.SendHandshakeProtectedPacket(packet)
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			err := conn.ProcessVersionNegotation(vn)
			if err != nil {
				return err
			}
			conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
		} else {
			defer spew.Dump(packet)
			return errors.New("Received incorrect packet type during handshake")
		}
	}

	return nil
}