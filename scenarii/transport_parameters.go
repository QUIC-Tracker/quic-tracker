package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"encoding/binary"

	"time"
)

const (
	TP_NoTPReceived     		= 1
	TP_TPResentAfterVN  		= 2  // All others error code are now handled by the handshake scenario
	TP_HandshakeDidNotComplete 	= 3
	TP_MissingParameters 		= 4  // Since draft-15, there are no parameters that MUST be present
)

type TransportParameterScenario struct {
	AbstractScenario
}

func NewTransportParameterScenario() *TransportParameterScenario {
	return &TransportParameterScenario{AbstractScenario{name: "transport_parameters", version: 3}}
}
func (s *TransportParameterScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	for i := uint16(0xff00); i <= 0xff0f; i++ {
		p := qt.TransportParameter{ParameterType: qt.TransportParametersType(i)}
		p.Value = make([]byte, 2, 2)
		binary.BigEndian.PutUint16(p.Value, i)
		conn.TLSTPHandler.AdditionalParameters.AddParameter(p)
	}

	connAgents := s.CompleteHandshake(conn, trace, TP_HandshakeDidNotComplete)
	if connAgents == nil {
		return
	}
	s.Finished()
	<-s.timeout.C
	defer connAgents.CloseConnection(false, 0, "")

	trace.Results["transport_parameters"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
	trace.Results["decoded_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON
}