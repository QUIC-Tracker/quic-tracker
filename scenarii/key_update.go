package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/mpiraux/pigotls"
	"time"
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
func (s *KeyUpdateScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, KU_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	// TODO: Move this to crypto.go
	readSecret := conn.Tls.HkdfExpandLabel(conn.Tls.ProtectedReadSecret(), "traffic upd", nil, conn.Tls.HashDigestSize(), pigotls.BaseLabel)
	writeSecret := conn.Tls.HkdfExpandLabel(conn.Tls.ProtectedWriteSecret(), "traffic upd", nil, conn.Tls.HashDigestSize(), pigotls.BaseLabel)

	oldState := conn.CryptoStates[qt.EncryptionLevel1RTT]

	conn.CryptoStates[qt.EncryptionLevel1RTT] = qt.NewProtectedCryptoState(conn.Tls, readSecret, writeSecret)
	conn.CryptoStates[qt.EncryptionLevel1RTT].HeaderRead = oldState.HeaderRead
	conn.CryptoStates[qt.EncryptionLevel1RTT].HeaderWrite = oldState.HeaderWrite
	conn.KeyPhaseIndex++

	conn.SendHTTP09GETRequest(preferredUrl, 0)

	<-s.Timeout().C

	if !conn.Streams.Get(0).ReadClosed {
		trace.ErrorCode = KU_HostDidNotRespond
	}
}
