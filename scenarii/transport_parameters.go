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
	m "masterthesis"
	"github.com/davecgh/go-spew/spew"
)

const (
	TP_NoTPReceived     = 1
	TP_TPResentAfterVN  = 2
	TP_VNDidNotComplete = 3
)

type TransportParameterScenario struct {
	AbstractScenario
}

func NewTransportParameterScenario() *TransportParameterScenario {
	return &TransportParameterScenario{AbstractScenario{"transport_parameters", 1, false}}
}
func (s *TransportParameterScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.SendInitialPacket()

	ongoingHandshake := true
	defer func() {
		if r := recover(); r != nil {
			if err, ok := r.(error); ok {
				println(err.Error())
			}
		}
		ongoingHandshake = false
	}()

	var receivedVN bool

	ongoingHandhake := true
	for ongoingHandhake {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			panic(err)
		}
		if scp, ok := packet.(*m.HandshakePacket); ok {
			ongoingHandhake, err = conn.ProcessServerHello(scp)
			if err != nil {
				panic(err)
			}
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			receivedVN = true

			if conn.TLSTPHandler.EncryptedExtensionsTransportParameters == nil {
				trace.ErrorCode = TP_NoTPReceived
			} else {
				trace.Results["transport_parameters"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
			}

			err = conn.ProcessVersionNegotation(vn)
			if err != nil {
				trace.ErrorCode = TP_VNDidNotComplete
				trace.Results["error"] = err
				return
			}
			conn.SendInitialPacket()
		} else {
			spew.Dump(packet)
			panic(packet)
		}
	}

	if !receivedVN {
		if conn.TLSTPHandler.EncryptedExtensionsTransportParameters == nil {
			trace.ErrorCode = TP_NoTPReceived
		} else {
			trace.Results["transport_parameters"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
		}
	} else if conn.TLSTPHandler.EncryptedExtensionsTransportParameters != nil {
		trace.ErrorCode = TP_TPResentAfterVN
		trace.Results["transport_parameters_after_VN"] = conn.TLSTPHandler.EncryptedExtensionsTransportParameters
	}

	conn.CloseConnection(false, 42, "")
}
