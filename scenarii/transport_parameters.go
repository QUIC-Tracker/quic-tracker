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
	return &TransportParameterScenario{AbstractScenario{"transport_parameters", 2, false}}
}
func (s *TransportParameterScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	conn.SendInitialPacket()

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			trace.ErrorCode = TP_HandshakeDidNotComplete
			trace.Results["error"] = err.Error()
			return
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, err = conn.ProcessServerHello(scp)
			if err != nil {
				trace.ErrorCode = TP_HandshakeDidNotComplete
				trace.Results["error"] = err.Error()
				return
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			err = conn.ProcessVersionNegotation(vn)
			if err != nil {
				trace.ErrorCode = TP_HandshakeDidNotComplete
				trace.Results["error"] = err.Error()
				return
			}
			conn.SendInitialPacket()
		} else {
			trace.Results["unexpected_packet_type"] = packet.Header().PacketType()
			trace.ErrorCode = TP_HandshakeDidNotComplete
			if debug {
				spew.Dump(packet)
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

	conn.CloseConnection(false, 0, "")
}

func validate(parameters map[string]interface{}) bool {
	_, present1 := parameters["initial_max_stream_data"]
	_, present2 := parameters["initial_max_data"]
	_, present3 := parameters["idle_timeout"]
	_, present4 := parameters["stateless_reset_token"]

	return !(present1 && present2 && present3 && present4)
}
