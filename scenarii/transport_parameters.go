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
	"encoding/binary"
)

const (
	TP_NoTPReceived     		= 1
	TP_TPResentAfterVN  		= 2
	TP_HandshakeDidNotComplete 	= 3
	TP_MissingParameters 		= 4
)

type TransportParameterScenario struct {
	AbstractScenario
}

func NewTransportParameterScenario() *TransportParameterScenario {
	return &TransportParameterScenario{AbstractScenario{"transport_parameters", 3, false}}
}
func (s *TransportParameterScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	for i := uint16(0xff00); i <= 0xff0f; i++ {
		p := m.TransportParameter{ParameterType: m.TransportParametersType(i)}
		p.Value = make([]byte, 2, 2)
		binary.BigEndian.PutUint16(p.Value, i)
		conn.TLSTPHandler.AdditionalParameters.AddParameter(p)
	}

	conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())

	ongoingHandhake := true
	var err error

outerLoop:
	for p := range conn.IncomingPackets {
		switch p := p.(type) {
		case *m.HandshakePacket, *m.RetryPacket:
			ongoingHandhake, p, err = conn.ProcessServerHello(p.(m.Framer))
			if err != nil {
				trace.MarkError(TP_HandshakeDidNotComplete, err.Error(), p)
				return
			}
			if p != nil {
				conn.SendHandshakeProtectedPacket(p)
			}
			if !ongoingHandhake {
				break outerLoop
			}
		case *m.VersionNegotationPacket:
			err = conn.ProcessVersionNegotation(p)
			if err != nil {
				trace.MarkError(TP_HandshakeDidNotComplete, err.Error(), p)
				return
			}
			conn.SendHandshakeProtectedPacket(conn.GetInitialPacket())
		default:
			trace.Results["unexpected_packet_type"] = p.Header().PacketType()
			trace.MarkError(TP_HandshakeDidNotComplete, "", p)
			if debug {
				spew.Dump(p)
			}
			return
		}
	}

	if conn.TLSTPHandler.EncryptedExtensionsTransportParameters == nil {
		trace.ErrorCode = TP_NoTPReceived
	} else {
		trace.Results["transport_parameters"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
		trace.Results["decoded_parameters"] = conn.TLSTPHandler.ReceivedParameters.ToJSON
	}

	if _, ok := trace.Results["decoded_parameter"]; ok && !validate(trace.Results["decoded_parameters"].(map[string]interface{})) {
		trace.ErrorCode = TP_MissingParameters
	}

	if conn.Protected != nil {
		conn.CloseConnection(false, 0, "")
	}
}

func validate(parameters map[string]interface{}) bool {
	_, present1 := parameters["initial_max_stream_data"]
	_, present2 := parameters["initial_max_data"]
	_, present3 := parameters["idle_timeout"]
	_, present4 := parameters["stateless_reset_token"]

	return !(present1 && present2 && present3 && present4)
}
