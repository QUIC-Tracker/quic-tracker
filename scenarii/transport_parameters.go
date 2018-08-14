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
	qt "github.com/QUIC-Tracker/quic-tracker"
	"encoding/binary"

	"time"
)

const (
	TP_NoTPReceived     		= 1
	TP_TPResentAfterVN  		= 2  // All others error code are now handled by the handshake scenario
	TP_HandshakeDidNotComplete 	= 3
	TP_MissingParameters 		= 4
)

type TransportParameterScenario struct {
	AbstractScenario
}

func NewTransportParameterScenario() *TransportParameterScenario {
	return &TransportParameterScenario{AbstractScenario{"transport_parameters", 3, false, nil}}
}
func (s *TransportParameterScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
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
	defer connAgents.CloseConnection(false, 0, "")

	trace.Results["transport_parameters"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
	trace.Results["decoded_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON

	if !validate(conn.TLSTPHandler.ReceivedParameters.ToJSON) {
		trace.MarkError(TP_MissingParameters, "", nil)
	}
}

func validate(parameters map[string]interface{}) bool {
	_, present1 := parameters["initial_max_stream_data"]
	_, present2 := parameters["initial_max_data"]
	_, present3 := parameters["idle_timeout"]

	return present1 && present2 && present3
}
