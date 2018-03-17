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
	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"encoding/binary"
)

const QuicTPExtensionType = mint.ExtensionType(26)  // https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-9.2

type TransportParametersType uint16
const (
	InitialMaxStreamData   TransportParametersType = 0x0000
	InitialMaxData         TransportParametersType = 0x0001
	InitialMaxStreamIdBidi TransportParametersType = 0x0002
	IdleTimeout            TransportParametersType = 0x0003
	OmitConnectionId       TransportParametersType = 0x0004 // TODO: Support the following parameters
	MaxPacketSize          TransportParametersType = 0x0005
	StatelessResetToken    TransportParametersType = 0x0006
	AckDelayExponent       TransportParametersType = 0x0007
	InitialMaxStreamIdUni  TransportParametersType = 0x0008
)

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	MaxStreamData       uint32
	MaxData             uint32
	MaxStreamIdBidi     uint32
	MaxStreamIdUni      uint32
	IdleTimeout         uint16
	OmitConnectionId    bool
	MaxPacketSize       uint16
	StatelessResetToken []byte
	AckDelayExponent    uint8
	ToJSON              map[string]interface{}
}

type TransportParameter struct {
	ParameterType TransportParametersType
	Value         []byte `tls:"head=2"`
}

type TransportParameterList []TransportParameter

func (list *TransportParameterList) getParameter(id TransportParametersType) []byte {
	for _, ex := range *list {
		if ex.ParameterType == id {
			return ex.Value
		}
	}
	return nil
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

type TPExtensionBody struct {
	body []byte
}

func (t TPExtensionBody) Type() mint.ExtensionType {
	return QuicTPExtensionType
}

func (t TPExtensionBody) Marshal() ([]byte, error) {
	return t.body, nil
}

func (t *TPExtensionBody) Unmarshal(data []byte) (int, error) {
	t.body = data
	return len(t.body), nil
}

type TLSTransportParameterHandler struct {
	NegotiatedVersion uint32
	InitialVersion    uint32
	QuicTransportParameters
	*EncryptedExtensionsTransportParameters
	ReceivedParameters *QuicTransportParameters
}

func NewTLSTransportParameterHandler(negotiatedVersion uint32, initialVersion uint32) *TLSTransportParameterHandler {
	return &TLSTransportParameterHandler{NegotiatedVersion: negotiatedVersion, InitialVersion: initialVersion, QuicTransportParameters: QuicTransportParameters{MaxStreamData: 16 * 1024, MaxData: 32 * 1024, MaxStreamIdBidi: 17, MaxStreamIdUni: 19, IdleTimeout: 10}}
}

func (h *TLSTransportParameterHandler) Send(hs mint.HandshakeType, el *mint.ExtensionList) error {
	if hs != mint.HandshakeTypeClientHello {
		panic(hs)
	}

	body, err := syntax.Marshal(ClientHelloTransportParameters{h.InitialVersion, TransportParameterList{
		{InitialMaxStreamData, Uint32ToBEBytes(h.QuicTransportParameters.MaxStreamData)},
		{InitialMaxData, Uint32ToBEBytes(h.QuicTransportParameters.MaxData)},
		{InitialMaxStreamIdBidi, Uint32ToBEBytes(h.QuicTransportParameters.MaxStreamIdBidi)},
		{IdleTimeout, Uint16ToBEBytes(h.QuicTransportParameters.IdleTimeout)},
	}})

	if err != nil {
		return err
	}

	el.Add(&TPExtensionBody{body})
	return nil
}

func (h *TLSTransportParameterHandler) Receive(hs mint.HandshakeType, el *mint.ExtensionList) error {
	var body TPExtensionBody
	ok, err := el.Find(&body)

	if !ok {
		return err
	}

	if hs == mint.HandshakeTypeEncryptedExtensions {
		if h.EncryptedExtensionsTransportParameters == nil {
			h.EncryptedExtensionsTransportParameters = &EncryptedExtensionsTransportParameters{}
		}
		_, err := syntax.Unmarshal(body.body, h.EncryptedExtensionsTransportParameters)
		if err != nil {
			panic(err)
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
				receivedParameters.MaxStreamIdBidi = binary.BigEndian.Uint32(p.Value)
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
				receivedParameters.MaxStreamIdUni = binary.BigEndian.Uint32(p.Value)
				receivedParameters.ToJSON["initial_max_stream_id_uni"] = receivedParameters.MaxStreamIdUni
			}
		}

		h.ReceivedParameters = &receivedParameters

	}

	return nil
}