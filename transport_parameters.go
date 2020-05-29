package quictracker

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/QUIC-Tracker/quic-tracker/lib"
)

type TransportParametersType uint64

const (
	OriginalDestinationConnectionId TransportParametersType = 0x00
	IdleTimeout                                             = 0x01
	StatelessResetToken                                     = 0x02
	MaxUDPPacketSize                                        = 0x03
	InitialMaxData                                          = 0x04
	InitialMaxStreamDataBidiLocal                           = 0x05
	InitialMaxStreamDataBidiRemote                          = 0x06
	InitialMaxStreamDataUni                                 = 0x07
	InitialMaxStreamsBidi                                   = 0x08
	InitialMaxStreamsUni                                    = 0x09
	AckDelayExponent                                        = 0x0a
	MaxAckDelay                                             = 0x0b
	DisableMigration                                        = 0x0c
	PreferredAddress                                        = 0x0d // TODO: Handle this parameter
	ActiveConnectionIdLimit                                 = 0x0e
	InitialSourceConnectionId                               = 0x0f
	RetrySourceConnectionId                                 = 0x10
)

type QuicTransportParameters struct {  // A set of QUIC transport parameters value
	OriginalDestinationConnectionId ConnectionID
	IdleTimeout                     uint64
	StatelessResetToken             []byte
	MaxPacketSize                   uint64
	MaxData                         uint64
	MaxStreamDataBidiLocal          uint64
	MaxStreamDataBidiRemote         uint64
	MaxStreamDataUni                uint64
	MaxBidiStreams                  uint64
	MaxUniStreams                   uint64
	AckDelayExponent                uint64
	MaxAckDelay                     uint64
	DisableMigration                bool
	PreferredAddress                []byte
	ActiveConnectionIdLimit         uint64
	InitialSourceConnectionId       ConnectionID
	RetrySourceConnectionId         ConnectionID
	AdditionalParameters            TransportParameterList
	ToJSON                          map[string]interface{}
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

type EncryptedExtensionsTransportParameters struct {
	TransportParameterList  `tls:"head=2"`
}

type TLSTransportParameterHandler struct {
	QuicTransportParameters
	*EncryptedExtensionsTransportParameters
	ReceivedParameters *QuicTransportParameters
}

func NewTLSTransportParameterHandler(scid ConnectionID) *TLSTransportParameterHandler {
	return &TLSTransportParameterHandler{QuicTransportParameters: QuicTransportParameters{MaxStreamDataBidiLocal: 16 * 1024, MaxStreamDataUni: 16 * 1024, MaxData: 32 * 1024, MaxBidiStreams: 1, MaxUniStreams: 3, IdleTimeout: 10000, AckDelayExponent: 3, ActiveConnectionIdLimit: 4, InitialSourceConnectionId: scid}}
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
		case []byte:
			parameters = append(parameters, TransportParameter{parametersType, val})
		case ConnectionID:
			parameters = append(parameters, TransportParameter{parametersType, []byte(val)})
		case bool:
			if !val {
				return
			}
			parameters = append(parameters, TransportParameter{parametersType, []byte{}})
		default:
			panic("the parameter value should be uint32, uint16, byte, bool, []byte or ConnectionID")
		}
	}

	addParameter(InitialMaxStreamDataBidiLocal, h.QuicTransportParameters.MaxStreamDataBidiLocal)
	addParameter(InitialMaxStreamDataUni, h.QuicTransportParameters.MaxStreamDataUni)
	addParameter(InitialMaxData, h.QuicTransportParameters.MaxData)
	addParameter(InitialMaxStreamsBidi, h.QuicTransportParameters.MaxBidiStreams)
	addParameter(InitialMaxStreamsUni, h.QuicTransportParameters.MaxUniStreams)
	addParameter(IdleTimeout, h.QuicTransportParameters.IdleTimeout)
	if h.QuicTransportParameters.ActiveConnectionIdLimit > 1 {
		addParameter(ActiveConnectionIdLimit, h.QuicTransportParameters.ActiveConnectionIdLimit)
	}
	if h.QuicTransportParameters.MaxPacketSize > 0 {
		addParameter(MaxUDPPacketSize, h.QuicTransportParameters.MaxPacketSize)
	}
	addParameter(InitialSourceConnectionId, h.QuicTransportParameters.InitialSourceConnectionId)
	for _, p := range h.QuicTransportParameters.AdditionalParameters {
		parameters = append(parameters, p)
	}

	data := bytes.NewBuffer(make([]byte, 0, 65535))
	for _, p := range parameters {
		_, err := data.Write(lib.EncodeVarInt(uint64(p.ParameterType)))
		if err != nil {
			return nil, err
		}
		_, err = data.Write(lib.EncodeVarInt(uint64(len(p.Value))))
		if err != nil {
			return nil, err
		}
		_, err = data.Write(p.Value)
		if err != nil {
			return nil, err
		}
	}
	return data.Bytes(), nil
}

func (h *TLSTransportParameterHandler) ReceiveExtensionData(data []byte) error {
	// TODO: Check for duplicates ?
	if h.EncryptedExtensionsTransportParameters == nil {
		h.EncryptedExtensionsTransportParameters = &EncryptedExtensionsTransportParameters{}
	}

	receivedParameters := QuicTransportParameters{}
	receivedParameters.ToJSON = make(map[string]interface{})

	buf := bytes.NewBuffer(data)

	for buf.Len() > 0 {
		pType, err := ReadVarInt(buf)
		if err != nil {
			return err
		}
		pLen, err := ReadVarInt(buf)
		if err != nil {
			return err
		}
		pData := make([]byte, pLen.Value)
		nRead, err := buf.Read(pData)
		if err != nil {
			return err
		}
		if uint64(nRead) != pLen.Value {
			return errors.New("end of TPs blob before parameter value")
		}
		pDataBuf := bytes.NewBuffer(pData)
		switch TransportParametersType(pType.Value) {
		case OriginalDestinationConnectionId:
			receivedParameters.OriginalDestinationConnectionId = ConnectionID(pDataBuf.Bytes())
			receivedParameters.ToJSON["original_destination_connection_id"] = ConnectionID(pData)
		case IdleTimeout:
			receivedParameters.IdleTimeout, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["idle_timeout"] = receivedParameters.IdleTimeout
		case StatelessResetToken:
			receivedParameters.StatelessResetToken = pDataBuf.Bytes()
			receivedParameters.ToJSON["stateless_reset_token"] = receivedParameters.StatelessResetToken
		case MaxUDPPacketSize:
			receivedParameters.MaxPacketSize, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["max_packet_size"] = receivedParameters.MaxPacketSize
		case InitialMaxData:
			receivedParameters.MaxData, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_data"] = receivedParameters.MaxData
		case InitialMaxStreamDataBidiLocal:
			receivedParameters.MaxStreamDataBidiLocal, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_stream_data_bidi_local"] = receivedParameters.MaxStreamDataBidiLocal
		case InitialMaxStreamDataBidiRemote:
			receivedParameters.MaxStreamDataBidiRemote, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_stream_data_bidi_remote"] = receivedParameters.MaxStreamDataBidiRemote
		case InitialMaxStreamDataUni:
			receivedParameters.MaxStreamDataUni, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_stream_data_uni"] = receivedParameters.MaxStreamDataUni
		case InitialMaxStreamsBidi:
			receivedParameters.MaxBidiStreams, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_streams_bidi"] = receivedParameters.MaxBidiStreams
		case InitialMaxStreamsUni:
			receivedParameters.MaxUniStreams, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["initial_max_streams_uni"] = receivedParameters.MaxUniStreams
		case AckDelayExponent:
			receivedParameters.AckDelayExponent, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["ack_delay_exponent"] = receivedParameters.AckDelayExponent
		case MaxAckDelay:
			receivedParameters.MaxAckDelay, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["max_ack_delay"] = receivedParameters.MaxAckDelay
		case DisableMigration:
			receivedParameters.DisableMigration = true
			receivedParameters.ToJSON["disable_migration"] = true
		case PreferredAddress:
			receivedParameters.PreferredAddress = pDataBuf.Bytes()
			receivedParameters.ToJSON["preferred_address"] = receivedParameters.PreferredAddress
		case ActiveConnectionIdLimit:
			receivedParameters.ActiveConnectionIdLimit, _, err = lib.ReadVarIntValue(pDataBuf)
			receivedParameters.ToJSON["active_connection_id_limit"] = receivedParameters.ActiveConnectionIdLimit
		case InitialSourceConnectionId:
			receivedParameters.InitialSourceConnectionId = ConnectionID(pDataBuf.Bytes())
			receivedParameters.ToJSON["initial_source_connection_id"] = ConnectionID(pData)
		case RetrySourceConnectionId:
			receivedParameters.RetrySourceConnectionId = ConnectionID(pDataBuf.Bytes())
			receivedParameters.ToJSON["retry_source_connection_id"] = ConnectionID(pData)
		default:
			p := TransportParameter{ParameterType: TransportParametersType(pType.Value), Value: pDataBuf.Bytes()}
			receivedParameters.AdditionalParameters.AddParameter(p)
			receivedParameters.ToJSON[fmt.Sprintf("%x", p.ParameterType)] = pDataBuf.Bytes()
		}
		if err != nil {
			return err
		}
	}

	h.ReceivedParameters = &receivedParameters

	return nil
}