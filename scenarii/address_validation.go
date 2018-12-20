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
	return &AddressValidationScenario{AbstractScenario{"address_validation", 2, false, nil}}
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
	var addressValidated bool
	ackTimer := time.NewTimer(3 * time.Second)

	trace.ErrorCode = AV_TLSHandshakeFailed

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

			if !addressValidated && float32(socketAgent.TotalDataReceived) / float32(initialLength) > 3.5 {
				trace.MarkError(AV_SentMoreThan3TimesAmount, "", i.(qt.Packet))
				ackTimer.Stop()
			} else if !addressValidated {
				ackTimer.Reset(3 * time.Second)
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
		case <-ackTimer.C:
			for pns, enc := range map[qt.PNSpace]qt.EncryptionLevel{qt.PNSpaceInitial: qt.EncryptionLevelInitial, qt.PNSpaceHandshake: qt.EncryptionLevelHandshake, qt.PNSpaceAppData: qt.EncryptionLevel1RTT} {
				f := conn.GetAckFrame(pns)
				if f != nil {
					conn.FrameQueue.Submit(qt.QueuedFrame{f, enc})
				}
			}
			addressValidated = true
			ackAgent.DisableAcks[qt.PNSpaceInitial] = false
			ackAgent.DisableAcks[qt.PNSpaceHandshake] = false
			ackAgent.DisableAcks[qt.PNSpaceAppData] = false
			tlsAgent.DisableFrameSending = false
			trace.Results["amplification_factor"] = float32(socketAgent.TotalDataReceived) / float32(initialLength)
		case <-s.Timeout().C:
			break forLoop
		}
	}

	trace.Results["datagrams_received"] = socketAgent.DatagramsReceived
	trace.Results["total_data_received"] = socketAgent.TotalDataReceived
	if trace.ErrorCode == AV_SentMoreThan3TimesAmount {
		trace.Results["amplification_factor"] = float32(socketAgent.TotalDataReceived) / float32(initialLength)
	}
}
