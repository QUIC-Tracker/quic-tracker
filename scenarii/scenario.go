//
// This package contains all the test scenarii that are part of the test suite. Each of them is executed in a separate
// connection. For executing scenarii, use the scripts in the bin/test_suite package.
//
// When adding a new scenario, one should comply with the following requirements:
//
// 	Its Name() must match its source code file without the extension.
// 	It must be registered in the GetAllScenarii() function.
// 	It must define an upper bound on its completion time. It should use the Timeout() function to achieve this.
//
//
package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"github.com/QUIC-Tracker/quic-tracker/agents"
	"time"
)

type Scenario interface {
	Name() string
	Version() int
	IPv6() bool
	HTTP3() bool
	Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool)
	SetTimer(d time.Duration)
	Timeout() <-chan time.Time
	Finished()
}

// Each scenario should embed this structure
type AbstractScenario struct {
	name     string
	version  int
	ipv6     bool
	http3    bool
	duration time.Duration
	timeout  *time.Timer
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
func (s *AbstractScenario) HTTP3() bool {
	return s.http3
}
func (s *AbstractScenario) SetTimer(d time.Duration) {
	s.timeout = time.NewTimer(d)
	if d == 0 {
		<-s.timeout.C
	}
	s.duration = d
}
func (s *AbstractScenario) Timeout() <-chan time.Time {
	return s.timeout.C
}
func (s *AbstractScenario) Finished() {
	if s.duration == 0 {
		s.timeout.Reset(0)
	}
}

// Useful helper for scenarii that requires the handshake to complete before executing their test and don't want to
// discern the cause of its failure.
func (s *AbstractScenario) CompleteHandshake(conn *qt.Connection, trace *qt.Trace, handshakeErrorCode uint8, additionalAgents ...agents.Agent) *agents.ConnectionAgents {
	connAgents := agents.AttachAgentsToConnection(conn, append(agents.GetDefaultAgents(), additionalAgents...)...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	connAgents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = connAgents.GetFrameProducingAgents()

	handshakeStatus := handshakeAgent.HandshakeStatus.RegisterNewChan(10)
	handshakeAgent.InitiateHandshake()

	select {
	case i := <-handshakeStatus:
		status := i.(agents.HandshakeStatus)
		if !status.Completed {
			trace.MarkError(handshakeErrorCode, status.Error.Error(), status.Packet)
			connAgents.StopAll()
			return nil
		}
	case <-conn.ConnectionClosed:
		trace.MarkError(handshakeErrorCode, "connection closed", nil)
		connAgents.StopAll()
		return nil
	case <-s.Timeout():
		trace.MarkError(handshakeErrorCode, "handshake timeout", nil)
		connAgents.StopAll()
		return nil
	}
	return connAgents
}

func GetAllScenarii() map[string]Scenario {
	return map[string]Scenario{
		"zero_rtt":                   NewZeroRTTScenario(),
		"connection_migration":       NewConnectionMigrationScenario(),
		"unsupported_tls_version":    NewUnsupportedTLSVersionScenario(),
		"stream_opening_reordering":  NewStreamOpeningReorderingScenario(),
		"multi_stream":               NewMultiStreamScenario(),
		"new_connection_id":          NewNewConnectionIDScenario(),
		"version_negotiation":        NewVersionNegotiationScenario(),
		"handshake":                  NewHandshakeScenario(),
		"handshake_v6":               NewHandshakev6Scenario(),
		"transport_parameters":       NewTransportParameterScenario(),
		"address_validation":         NewAddressValidationScenario(),
		"padding":                    NewPaddingScenario(),
		"flow_control":               NewFlowControlScenario(),
		"ack_only":                   NewAckOnlyScenario(),
		"ack_ecn":                    NewAckECNScenario(),
		"stop_sending":               NewStopSendingOnReceiveStreamScenario(),
		"http_get_and_wait":          NewSimpleGetAndWaitScenario(),
		"http_get_on_uni_stream":     NewGetOnStream2Scenario(),
		"key_update":                 NewKeyUpdateScenario(),
		"retire_connection_id":       NewRetireConnectionIDScenario(),
		"http3_get":                  NewHTTP3GETScenario(),
		"http3_encoder_stream":       NewHTTP3EncoderStreamScenario(),
		"http3_uni_streams_limits":   NewHTTP3UniStreamsLimitsScenario(),
		"http3_reserved_frames":      NewHTTP3ReservedFramesScenario(),
		"http3_reserved_streams":     NewHTTP3ReservedStreamsScenario(),
		"spin_bit":                   NewSpinBitScenario(),
		"server_flow_control":        NewServerFlowControlScenario(),
		"connection_migration_v4_v6": NewConnectionMigrationv4v6Scenario(),
		"zero_length_cid": 			  NewZeroLengthCID(),
		"multi_packet_client_hello":  NewMultiPacketClientHello(),
		"closed_connection":          NewClosedConnectionScenario(),
	}
}
