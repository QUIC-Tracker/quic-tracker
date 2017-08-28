package main

type Encoder interface {
	toBytes() []byte
}

//func fromBytes(b *[]byte) Decoder


const QuicVersion uint32 = 0xff000005  // See https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-4

type TransportParametersType uint16
const InitialMaxStreamData 	TransportParametersType = 0x00
const InitialMaxData 		TransportParametersType = 0x01
const InitialMaxStreamId	TransportParametersType = 0x02
const IdleTimeout			TransportParametersType = 0x03
const OmitConnectionId		TransportParametersType = 0x04
const MaxPacketSize			TransportParametersType = 0x05
const StatelessResetToken	TransportParametersType = 0x06

type TransportParameter struct {
	parameterType TransportParametersType
	value uint16
}

