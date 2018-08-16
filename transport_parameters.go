package quictracker

import (
	"encoding/binary"
	"github.com/bifurcation/mint/syntax"
	"fmt"
)

type TransportParametersType uint16
const (
	InitialMaxStreamDataBidiLocal TransportParametersType = 0x0000
	InitialMaxData                                        = 0x0001
	InitialMaxBidiStreams                                 = 0x0002
	IdleTimeout                                           = 0x0003
	PreferredAddress                                      = 0x0004  // TODO: Handle this parameter
	MaxPacketSize                                         = 0x0005
	StatelessResetToken                                   = 0x0006
	AckDelayExponent                                      = 0x0007
	InitialMaxUniStreams                                  = 0x0008
	DisableMigration                             	      = 0x0009  // TODO: Handle this parameter
	InitialMaxStreamDataBidiRemote						  = 0x000a
	InitialMaxStreamDataUni								  = 0x000b
)

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	MaxStreamDataBidiLocal  uint32
	MaxData                 uint32
	MaxBidiStreams          uint16
	MaxUniStreams           uint16
	IdleTimeout             uint16
	PreferredAddress        string
	MaxPacketSize           uint16
	StatelessResetToken     []byte
	AckDelayExponent        uint8
	DisableMigration        bool
	MaxStreamDataBidiRemote uint32
	MaxStreamDataUni        uint32
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
		QuicTransportParameters{MaxStreamDataBidiLocal: 16 * 1024, MaxData: 32 * 1024, MaxBidiStreams: 1, MaxUniStreams: 1, IdleTimeout: 10}}
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

	addParameter(InitialMaxStreamDataBidiLocal, h.QuicTransportParameters.MaxStreamDataBidiLocal)
	addParameter(InitialMaxData, h.QuicTransportParameters.MaxData)
	addParameter(InitialMaxBidiStreams, h.QuicTransportParameters.MaxBidiStreams)
	addParameter(InitialMaxUniStreams, h.QuicTransportParameters.MaxUniStreams)
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
		case InitialMaxStreamDataBidiLocal:
			receivedParameters.MaxStreamDataBidiLocal = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_stream_data_bidi_local"] = receivedParameters.MaxStreamDataBidiLocal
		case InitialMaxData:
			receivedParameters.MaxData = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_data"] = receivedParameters.MaxData
		case InitialMaxBidiStreams:
			receivedParameters.MaxBidiStreams = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["initial_max_bidi_streams"] = receivedParameters.MaxBidiStreams
		case IdleTimeout:
			receivedParameters.IdleTimeout = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["idle_timeout"] = receivedParameters.IdleTimeout
		case PreferredAddress:
			receivedParameters.PreferredAddress = string(p.Value)
			receivedParameters.ToJSON["preferredAddress"] = receivedParameters.PreferredAddress
		case MaxPacketSize:
			receivedParameters.MaxPacketSize = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["max_packet_size"] = receivedParameters.MaxPacketSize
		case StatelessResetToken:
			receivedParameters.StatelessResetToken = p.Value
			receivedParameters.ToJSON["stateless_reset_token"] = receivedParameters.StatelessResetToken
		case AckDelayExponent:
			receivedParameters.AckDelayExponent = p.Value[0]
			receivedParameters.ToJSON["ack_delay_exponent"] = receivedParameters.AckDelayExponent
		case InitialMaxUniStreams:
			receivedParameters.MaxUniStreams = binary.BigEndian.Uint16(p.Value)
			receivedParameters.ToJSON["initial_max_uni_streams"] = receivedParameters.MaxUniStreams
		case DisableMigration:
			receivedParameters.DisableMigration = true
			receivedParameters.ToJSON["disable_migration"] = true
		case InitialMaxStreamDataBidiRemote:
			receivedParameters.MaxStreamDataBidiRemote = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_stream_data_bidi_remote"] = receivedParameters.MaxStreamDataBidiRemote
		case InitialMaxStreamDataUni:
			receivedParameters.MaxStreamDataUni = binary.BigEndian.Uint32(p.Value)
			receivedParameters.ToJSON["initial_max_stream_data_uni"] = receivedParameters.MaxStreamDataUni
		default:
			receivedParameters.AdditionalParameters.AddParameter(p)
			receivedParameters.ToJSON[fmt.Sprintf("%x", p.ParameterType)] = p.Value
		}
	}

	h.ReceivedParameters = &receivedParameters

	return nil
}