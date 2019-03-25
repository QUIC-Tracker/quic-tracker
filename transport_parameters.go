package quictracker

import (
	"bytes"
	"fmt"
	"github.com/QUIC-Tracker/quic-tracker/lib"
	"github.com/bifurcation/mint/syntax"
)

type TransportParametersType uint16

const (
	OriginalConnectionId           TransportParametersType = 0x0000
	IdleTimeout                                            = 0x0001
	StatelessResetToken                                    = 0x0002
	MaxPacketSize                                          = 0x0003
	InitialMaxData                                         = 0x0004
	InitialMaxStreamDataBidiLocal                          = 0x0005
	InitialMaxStreamDataBidiRemote                         = 0x0006
	InitialMaxStreamDataUni                                = 0x0007
	InitialMaxStreamsBidi                                  = 0x0008
	InitialMaxStreamsUni                                   = 0x0009
	AckDelayExponent                                       = 0x000a
	MaxAckDelay                                            = 0x000b
	DisableMigration                                       = 0x000c // TODO: Handle this parameter
	PreferredAddress                                       = 0x000d // TODO: Handle this parameter
)

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	OriginalConnectionId    ConnectionID
	IdleTimeout             uint64
	StatelessResetToken     []byte
	MaxPacketSize           uint64
	MaxData                 uint64
	MaxStreamDataBidiLocal  uint64
	MaxStreamDataBidiRemote uint64
	MaxStreamDataUni        uint64
	MaxBidiStreams          uint64
	MaxUniStreams           uint64
	AckDelayExponent        uint64
	MaxAckDelay				uint64
	DisableMigration        bool
	PreferredAddress        []byte
	AdditionalParameters    TransportParameterList
	ToJSON                  map[string]interface{}
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
		QuicTransportParameters{MaxStreamDataBidiLocal: 16 * 1024, MaxStreamDataUni: 16 * 1024, MaxData: 32 * 1024, MaxBidiStreams: 1, MaxUniStreams: 1, IdleTimeout: 10, AckDelayExponent: 3}}
}
func (h *TLSTransportParameterHandler) GetExtensionData() ([]byte, error) {
	var parameters []TransportParameter
	addParameter := func(parametersType TransportParametersType, value interface{}){
		switch val := value.(type) {
		case uint64: // Assumes it is varint then
			parameters = append(parameters, TransportParameter{parametersType, lib.EncodeVarInt(val)})
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

	addParameter(InitialMaxStreamDataBidiLocal, h.QuicTransportParameters.MaxStreamDataBidiLocal)
	addParameter(InitialMaxStreamDataUni, h.QuicTransportParameters.MaxStreamDataUni)
	addParameter(InitialMaxData, h.QuicTransportParameters.MaxData)
	addParameter(InitialMaxStreamsBidi, h.QuicTransportParameters.MaxBidiStreams)
	addParameter(InitialMaxStreamsUni, h.QuicTransportParameters.MaxUniStreams)
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
		case OriginalConnectionId:
			receivedParameters.OriginalConnectionId = ConnectionID(p.Value)
			receivedParameters.ToJSON["original_connection_id"] = ConnectionID(p.Value)
		case IdleTimeout:
			receivedParameters.IdleTimeout, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["idle_timeout"] = receivedParameters.IdleTimeout
		case StatelessResetToken:
			receivedParameters.StatelessResetToken = p.Value
			receivedParameters.ToJSON["stateless_reset_token"] = receivedParameters.StatelessResetToken
		case MaxPacketSize:
			receivedParameters.MaxPacketSize, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["max_packet_size"] = receivedParameters.MaxPacketSize
		case InitialMaxData:
			receivedParameters.MaxData, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_data"] = receivedParameters.MaxData
		case InitialMaxStreamDataBidiLocal:
			receivedParameters.MaxStreamDataBidiLocal, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_stream_data_bidi_local"] = receivedParameters.MaxStreamDataBidiLocal
		case InitialMaxStreamDataBidiRemote:
			receivedParameters.MaxStreamDataBidiRemote, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_stream_data_bidi_remote"] = receivedParameters.MaxStreamDataBidiRemote
		case InitialMaxStreamDataUni:
			receivedParameters.MaxStreamDataUni, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_stream_data_uni"] = receivedParameters.MaxStreamDataUni
		case InitialMaxStreamsBidi:
			receivedParameters.MaxBidiStreams, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_streams_bidi"] = receivedParameters.MaxBidiStreams
		case InitialMaxStreamsUni:
			receivedParameters.MaxUniStreams, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["initial_max_streams_uni"] = receivedParameters.MaxUniStreams
		case AckDelayExponent:
			receivedParameters.AckDelayExponent, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["ack_delay_exponent"] = receivedParameters.AckDelayExponent
		case MaxAckDelay:
			receivedParameters.MaxAckDelay, err = lib.ReadVarIntValue(bytes.NewReader(p.Value))
			receivedParameters.ToJSON["max_ack_delay"] = receivedParameters.MaxAckDelay
		case DisableMigration:
			receivedParameters.DisableMigration = true
			receivedParameters.ToJSON["disable_migration"] = true
		case PreferredAddress:
			receivedParameters.PreferredAddress = p.Value
			receivedParameters.ToJSON["preferredAddress"] = receivedParameters.PreferredAddress
		default:
			receivedParameters.AdditionalParameters.AddParameter(p)
			receivedParameters.ToJSON[fmt.Sprintf("%x", p.ParameterType)] = p.Value
		}
		if err != nil {
			return err
		}
	}

	h.ReceivedParameters = &receivedParameters

	return nil
}