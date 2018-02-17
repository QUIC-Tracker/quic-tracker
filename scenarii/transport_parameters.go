package scenarii

import (
	m "masterthesis"
	"github.com/davecgh/go-spew/spew"
)

const (
	TP_NoTPReceived    = 1
	TP_TPResentAfterVN = 2
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

			conn.ProcessVersionNegotation(vn)
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
