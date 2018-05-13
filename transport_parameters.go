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
package masterthesis

import (
	"encoding/binary"
	"github.com/bifurcation/mint/syntax"
)

type TransportParametersType uint16
const (
	InitialMaxStreamData   TransportParametersType = 0x0000
	InitialMaxData         TransportParametersType = 0x0001
	InitialMaxStreamIdBidi TransportParametersType = 0x0002
	IdleTimeout            TransportParametersType = 0x0003
	OmitConnectionId       TransportParametersType = 0x0004 // Unused since draft-11
	MaxPacketSize          TransportParametersType = 0x0005
	StatelessResetToken    TransportParametersType = 0x0006
	AckDelayExponent       TransportParametersType = 0x0007
	InitialMaxStreamIdUni  TransportParametersType = 0x0008
)

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	MaxStreamData        uint32
	MaxData              uint32
	MaxStreamIdBidi      uint16
	MaxStreamIdUni       uint16
	IdleTimeout          uint16
	OmitConnectionId     bool
	MaxPacketSize        uint16
	StatelessResetToken  []byte
	AckDelayExponent     uint8
	AdditionalParameters TransportParameterList
	ToJSON               map[string]interface{}
}

type TransportParameter struct {
	ParameterType TransportParametersType
	Value         []byte `tls:"head=2"`
}

type TransportParameterList []TransportParameter

func (list *TransportParameterList) GetParameter(id TransportParametersType) []byte {
	for _, ex := range *list {
		if ex.ParameterType == id {
			return ex.Value
		}
	}
	return nil
}

func (list *TransportParameterList) AddParameter(p TransportParameter) {
	*list = append(*list, p)
}

type ClientHelloTransportParameters struct {
	InitialVersion    uint32
	Parameters        TransportParameterList `tls:"head=2"`
}

type EncryptedExtensionsTransportParameters struct {
	NegotiatedVersion uint32
	SupportedVersions []SupportedVersion `tls:"head=1"`
	Parameters        TransportParameterList  `tls:"head=2"`
}

type TLSTransportParameterHandler struct {
	NegotiatedVersion uint32
	InitialVersion    uint32
	QuicTransportParameters
	*EncryptedExtensionsTransportParameters
	ReceivedParameters *QuicTransportParameters
}

func NewTLSTransportParameterHandler(negotiatedVersion uint32, initialVersion uint32) *TLSTransportParameterHandler {
	return &TLSTransportParameterHandler{NegotiatedVersion: negotiatedVersion, InitialVersion: initialVersion, QuicTransportParameters:
		QuicTransportParameters{MaxStreamData: 16 * 1024, MaxData: 32 * 1024, MaxStreamIdBidi: 1, MaxStreamIdUni: 1, IdleTimeout: 10}}
}
func (h *TLSTransportParameterHandler) GetExtensionData() ([]byte, error) {
	var parameters []TransportParameter
	addParameter := func(parametersType TransportParametersType, value interface{}){
		switch val := value.(type) {
		case uint32:
			if val == 0 {
				return
			}
			parameters = append(parameters, TransportParameter{parametersType, Uint32ToBEBytes(val)})
		case uint16:
			if val == 0 {
				return
			}
			parameters = append(parameters, TransportParameter{parametersType, Uint16ToBEBytes(val)})
		case byte:
			if val == 0 {
				return
			}
			parameters = append(parameters, TransportParameter{parametersType, []byte{val}})
		case bool:
			if !val {
				return
			}
			parameters = append(parameters, TransportParameter{parametersType, []byte{}})
		default:
			panic("the parameter value should be uint32, uint16, byte, bool or []byte")
		}
	}

	addParameter(InitialMaxStreamData, h.QuicTransportParameters.MaxStreamData)
	addParameter(InitialMaxData, h.QuicTransportParameters.MaxData)
	addParameter(InitialMaxStreamIdBidi, h.QuicTransportParameters.MaxStreamIdBidi)
	addParameter(InitialMaxStreamIdUni, h.QuicTransportParameters.MaxStreamIdUni)
	addParameter(IdleTimeout, h.QuicTransportParameters.IdleTimeout)
	for _, p := range h.QuicTransportParameters.AdditionalParameters {
		parameters = append(parameters, p)
	}
	return syntax.Marshal(ClientHelloTransportParameters{h.InitialVersion, TransportParameterList(parameters)})
}

func (h *TLSTransportParameterHandler) ReceiveExtensionData(data []byte) error {
	if h.EncryptedExtensionsTransportParameters == nil {
		h.EncryptedExtensionsTransportParameters = &EncryptedExtensionsTransportParameters{}
	}
	_, err := syntax.Unmarshal(data, h.EncryptedExtensionsTransportParameters)
	if err != nil {
		return err
	}

	receivedParameters := QuicTransportParameters{}
	receivedParameters.ToJSON = make(map[string]interface{})

	for _, p := range h.EncryptedExtensionsTransportParameters.Parameters {
		switch p.ParameterType {
		case InitialMaxStreamData:
			receivedParameters.MaxStreamData = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_stream_data"] = receivedParameters.MaxStreamData
		case InitialMaxData:
			receivedParameters.MaxData = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_data"] = receivedParameters.MaxData
		case InitialMaxStreamIdBidi:
			receivedParameters.MaxStreamIdBidi = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["initial_max_stream_id_bidi"] = receivedParameters.MaxStreamIdBidi
		case IdleTimeout:
			receivedParameters.IdleTimeout = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["idle_timeout"] = receivedParameters.IdleTimeout
		case OmitConnectionId:
			receivedParameters.OmitConnectionId = true
			receivedParameters.ToJSON["omit_connection_id"] = receivedParameters.OmitConnectionId
		case MaxPacketSize:
			receivedParameters.MaxPacketSize = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["max_packet_size"] = receivedParameters.MaxPacketSize
		case StatelessResetToken:
			receivedParameters.StatelessResetToken = p.Value
			receivedParameters.ToJSON["stateless_reset_token"] = receivedParameters.StatelessResetToken
		case AckDelayExponent:
			receivedParameters.AckDelayExponent = p.Value[0]
			receivedParameters.ToJSON["ack_delay_exponent"] = receivedParameters.AckDelayExponent
		case InitialMaxStreamIdUni:
			receivedParameters.MaxStreamIdUni = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["initial_max_stream_id_uni"] = receivedParameters.MaxStreamIdUni
		default:
			receivedParameters.AdditionalParameters.AddParameter(p)
			receivedParameters.ToJSON[string(p.ParameterType)] = p.Value
		}
	}

	h.ReceivedParameters = &receivedParameters

	return nil
}