package main

import (
	"github.com/bifurcation/mint"
	"github.com/bifurcation/mint/syntax"
	"encoding/binary"
	"bytes"
	"github.com/davecgh/go-spew/spew"
)

const QuicTPExtensionType = mint.ExtensionType(26) // See https://tools.ietf.org/html/draft-ietf-quic-tls-06#section-10.2

type TransportParametersType uint16
const InitialMaxStreamData 	TransportParametersType = 0x00
const InitialMaxData 		TransportParametersType = 0x01
const InitialMaxStreamId	TransportParametersType = 0x02
const IdleTimeout			TransportParametersType = 0x03
const OmitConnectionId		TransportParametersType = 0x04  // TODO: Support the following parameters
const MaxPacketSize			TransportParametersType = 0x05
const StatelessResetToken	TransportParametersType = 0x06

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	MaxStreamData uint32
	MaxData 	  uint32
	MaxStreamId   uint32
	IdleTimeout   uint16
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
	negotiatedVersion uint32
	initialVersion    uint32
	Parameters        TransportParameterList `tls:"head=2"`
}

type EncryptedExtensionsTransportParameters struct {
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

func (t TPExtensionBody) Unmarshal(data []byte) (int, error) {
	t.body = data
	return len(t.body), nil
}

type TLSTransportParameterHandler struct {
	QuicTransportParameters
}

func NewTLSTransportParameterHandler() *TLSTransportParameterHandler {
	return &TLSTransportParameterHandler{QuicTransportParameters{8 * 1024, 8 * 1024, 16, 10}}
}

func (h TLSTransportParameterHandler) Send(hs mint.HandshakeType, el *mint.ExtensionList) error {
	if hs != mint.HandshakeTypeClientHello {
		panic(hs)
	}

	body, err := syntax.Marshal(ClientHelloTransportParameters{QuicVersion, QuicVersion, TransportParameterList{
		{InitialMaxStreamData, Uint32ToBEBytes(h.QuicTransportParameters.MaxStreamData)},
		{InitialMaxData, Uint32ToBEBytes(h.QuicTransportParameters.MaxData)},
		{InitialMaxStreamId, Uint32ToBEBytes(h.QuicTransportParameters.MaxStreamId)},
		{IdleTimeout, Uint16ToBEBytes(h.QuicTransportParameters.IdleTimeout)},
	}})

	if err != nil {
		return err
	}

	el.Add(&TPExtensionBody{body})
	return nil
}

func (h TLSTransportParameterHandler) Receive(hs mint.HandshakeType, el *mint.ExtensionList) error {
	var list *TransportParameterList
	var body TPExtensionBody
	ok := el.Find(body)

	if !ok {
		return nil
	}

	if hs != mint.HandshakeTypeEncryptedExtensions {  // TODO: Verify this non equality check, or even that client can receive TPs.
		var eep EncryptedExtensionsTransportParameters
		_, err := syntax.Unmarshal(body.body, &eep)
		if err != nil {
			panic(err)
		}
		list = &eep.Parameters
		binary.Read(bytes.NewBuffer(list.getParameter(InitialMaxStreamData)), binary.BigEndian, &h.QuicTransportParameters.MaxStreamData)
		binary.Read(bytes.NewBuffer(list.getParameter(InitialMaxData)), binary.BigEndian, &h.QuicTransportParameters.MaxData)
		binary.Read(bytes.NewBuffer(list.getParameter(InitialMaxStreamId)), binary.BigEndian, &h.QuicTransportParameters.MaxStreamId)
		binary.Read(bytes.NewBuffer(list.getParameter(IdleTimeout)), binary.BigEndian, &h.QuicTransportParameters.IdleTimeout)
		spew.Dump(h)
	}

	return nil
}