package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"time"
)

const (
	MPCH_TLSHandshakeFailed = 1
	MPCH_RequestFailed      = 2
)

type MultiPacketClientHello struct {
	AbstractScenario
}

func NewMultiPacketClientHello() *MultiPacketClientHello {
	return &MultiPacketClientHello{AbstractScenario{name: "multi_packet_client_hello", version: 1}}
}

func (s *MultiPacketClientHello) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	connAgents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = connAgents.GetFrameProducingAgents()

	handshakeStatus := handshakeAgent.HandshakeStatus.RegisterNewChan(10)

	originalPacket := conn.GetInitialPacket()
	originalLen := len(originalPacket.Encode(originalPacket.EncodePayload()))
	f := originalPacket.GetFirst(qt.CryptoType).(*qt.CryptoFrame)
	secondPacket := qt.NewInitialPacket(conn)
	secondPacket.AddFrame(&qt.CryptoFrame{Offset: f.Length / 2, Length: f.Length - (f.Length / 2), CryptoData:f.CryptoData[f.Length/2:]})
	secondPacket.PadTo(originalLen)
	f.CryptoData = f.CryptoData[:f.Length/2]
	f.Length /= 2
	originalPacket.PadTo(originalLen)

	conn.DoSendPacket(secondPacket, qt.EncryptionLevelInitial)
	<-time.NewTimer(1 * time.Millisecond).C
	conn.DoSendPacket(originalPacket, qt.EncryptionLevelInitial)

	select {
	case i := <-handshakeStatus:
		status := i.(agents.HandshakeStatus)
		if !status.Completed {
			trace.MarkError(MPCH_TLSHandshakeFailed, status.Error.Error(), status.Packet)
			connAgents.StopAll()
			return
		} else {
			defer connAgents.CloseConnection(false, 0, "")
		}
	case <-conn.ConnectionClosed:
		trace.MarkError(MPCH_TLSHandshakeFailed, "connection closed", nil)
		connAgents.StopAll()
		return
	case <-s.Timeout():
		trace.MarkError(MPCH_TLSHandshakeFailed, "handshake timeout", nil)
		connAgents.StopAll()
		return
	}

	connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)

	<-s.Timeout()

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = MPCH_RequestFailed
	}
}
