package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"time"
)

const (
	AV_TLSHandshakeFailed       = 1
	AV_SentMoreThan3Datagrams   = 2
	AV_SentMoreThan3TimesAmount = 3
)

type AddressValidationScenario struct {
	AbstractScenario
}

func NewAddressValidationScenario() *AddressValidationScenario {
	return &AddressValidationScenario{AbstractScenario{name: "address_validation", version: 3}}
}
func (s *AddressValidationScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	defer connAgents.StopAll()

	ackAgent := connAgents.Get("AckAgent").(*agents.AckAgent)
	ackAgent.DisableAcks[qt.PNSpaceInitial] = true
	ackAgent.DisableAcks[qt.PNSpaceHandshake] = true
	ackAgent.DisableAcks[qt.PNSpaceAppData] = true
	socketAgent := connAgents.Get("SocketAgent").(*agents.SocketAgent)
	tlsAgent := connAgents.Get("TLSAgent").(*agents.TLSAgent)
	tlsAgent.DisableFrameSending = true

	handshakeAgent := &agents.HandshakeAgent{TLSAgent: tlsAgent, SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	handshakeAgent.IgnoreRetry = true
	connAgents.Add(handshakeAgent)
	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	outgoingPackets := make(chan interface{}, 1000)
	conn.OutgoingPackets.Register(outgoingPackets)

	handshakeAgent.InitiateHandshake()

	var arrivals []uint64
	var start time.Time
	var initialLength int

	trace.ErrorCode = 0

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			var isRetransmit bool
			switch p := i.(type) {
			case *qt.InitialPacket:
				if p.Contains(qt.CryptoType) {
					for _, f := range p.GetAll(qt.CryptoType) {
						if f.(*qt.CryptoFrame).Offset == 0 {
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
				if len(arrivals) > 1 {
					trace.Results["arrival_times"] = arrivals
				}
			}

			if float32(socketAgent.TotalDataReceived) / float32(initialLength) > 3.5 {
				trace.MarkError(AV_SentMoreThan3TimesAmount, "", i.(qt.Packet))
			}
		case i := <-outgoingPackets:
			p := i.(qt.Packet)
			if p.Header().PacketNumber() == 0 && p.Header().PacketType() == qt.Initial {
				initialLength = len(p.Encode(p.EncodePayload()))
			}
		case i := <-handshakeStatus:
			status := i.(agents.HandshakeStatus)
			if !status.Completed {
				trace.MarkError(AV_TLSHandshakeFailed, status.Error.Error(), status.Packet)
				break forLoop
			} else {
				defer connAgents.CloseConnection(false, 0, "")
				trace.ErrorCode = 0
			}
		case <-s.Timeout().C:
			break forLoop
		}
	}

	trace.Results["amplification_factor"] = float32(socketAgent.TotalDataReceived) / float32(initialLength)
	trace.Results["datagrams_received"] = socketAgent.DatagramsReceived
	trace.Results["total_data_received"] = socketAgent.TotalDataReceived
}
