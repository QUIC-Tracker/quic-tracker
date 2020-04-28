package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/mpiraux/pigotls"
)

const (
	KU_TLSHandshakeFailed = 1
	KU_HostDidNotRespond  = 2
)

type KeyUpdateScenario struct {
	AbstractScenario
}

func NewKeyUpdateScenario() *KeyUpdateScenario {
	return &KeyUpdateScenario{AbstractScenario{name: "key_update", version: 1}}
}
func (s *KeyUpdateScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, KU_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	conn.FrameQueue.Submit(qt.QueuedFrame{Frame: new(qt.PingFrame), EncryptionLevel: qt.EncryptionLevel1RTT})
	ackedPackets := conn.PacketAcknowledged.RegisterNewChan(10)
forLoop1:
	for {
		select {
		case i := <-ackedPackets:
			switch a := i.(type) {
			case qt.PacketAcknowledged:
				if a.PNSpace == qt.PNSpaceAppData {
					conn.PacketAcknowledged.Unregister(ackedPackets)
					break forLoop1
				}
			}
		case <-conn.ConnectionClosed:
			trace.ErrorCode = KU_TLSHandshakeFailed
			return
		case <-s.Timeout():
			trace.ErrorCode = KU_TLSHandshakeFailed
			return
		}
	}

	// TODO: Move this to crypto.go
	readSecret := conn.Tls.HkdfExpandLabel(conn.Tls.ProtectedReadSecret(), "ku", nil, conn.Tls.HashDigestSize(), pigotls.QuicBaseLabel)
	writeSecret := conn.Tls.HkdfExpandLabel(conn.Tls.ProtectedWriteSecret(), "ku", nil, conn.Tls.HashDigestSize(), pigotls.QuicBaseLabel)

	conn.CryptoStateLock.Lock()
	oldState := conn.CryptoStates[qt.EncryptionLevel1RTT]

	conn.CryptoStates[qt.EncryptionLevel1RTT] = qt.NewProtectedCryptoState(conn.Tls, readSecret, writeSecret)
	conn.CryptoStates[qt.EncryptionLevel1RTT].HeaderRead = oldState.HeaderRead
	conn.CryptoStates[qt.EncryptionLevel1RTT].HeaderWrite = oldState.HeaderWrite
	conn.KeyPhaseIndex++
	conn.CryptoStateLock.Unlock()

	responseChan := connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)

forLoop2:
	for {
		select {
		case <-responseChan:
			s.Finished()
		case <-conn.ConnectionClosed:
			break forLoop2
		case <-s.Timeout():
			break forLoop2
		}
	}

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = KU_HostDidNotRespond
	}
}
