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
	"github.com/mpiraux/master-thesis/agents"
	"time"
	"fmt"
)

const (
	AV_TLSHandshakeFailed = 1
	AV_SentMoreThan3Datagrams = 2
)

type AddressValidationScenario struct {
	AbstractScenario
}

func NewAddressValidationScenario() *AddressValidationScenario {
	return &AddressValidationScenario{AbstractScenario{"address_validation", 1, false, nil}}
}
func (s *AddressValidationScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	defer connAgents.StopAll()

	connAgents.Get("AckAgent").(*agents.AckAgent).Stop()
	socketAgent := connAgents.Get("SocketAgent").(*agents.SocketAgent)
	tlsAgent := connAgents.Get("TLSAgent").(*agents.TLSAgent)
	tlsAgent.DisableFrameSending = true

	handshakeAgent := &agents.HandshakeAgent{TLSAgent: tlsAgent, SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	handshakeAgent.InitiateHandshake()

	var arrivals []uint64
	var start time.Time

	trace.ErrorCode = AV_TLSHandshakeFailed

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			var isRetransmit bool
			switch p := i.(type) {
			case *m.InitialPacket:
				if p.Contains(m.CryptoType) {
					for _, f := range p.GetAll(m.CryptoType) {
						if f.(*m.CryptoFrame).Offset == 0 {
							isRetransmit = true
						}
					}
				}
			}

			if isRetransmit {
				if start.IsZero() {
					start = time.Now()
				}
				arrivals = append(arrivals, uint64(time.Now().Sub(start).Seconds()*1000))
			}

			if socketAgent.DatagramsReceived > 3 {
				trace.MarkError(AV_SentMoreThan3Datagrams, fmt.Sprintf("%d datagrams received", socketAgent.DatagramsReceived), i.(m.Packet))
			}
		case i := <-handshakeStatus:
			status := i.(agents.HandshakeStatus)
			if !status.Completed {
				trace.MarkError(AV_TLSHandshakeFailed, status.Error.Error(), status.Packet)
				break forLoop
			} else {
				trace.ErrorCode = 0
			}
		case <-s.Timeout().C:
			break forLoop
		}
	}

	trace.Results["arrival_times"] = arrivals
	trace.Results["datagrams_received"] = socketAgent.DatagramsReceived
	trace.Results["total_data_received"] = socketAgent.TotalDataReceived
	// TODO: Compute amplification factor
}