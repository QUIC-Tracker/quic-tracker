package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"time"
)

const (
	CM_TLSHandshakeFailed        = 1
	CM_UDPConnectionFailed       = 2
	CM_HostDidNotMigrate         = 3
	CM_HostDidNotValidateNewPath = 4
)

type ConnectionMigrationScenario struct {
	AbstractScenario
}

func NewConnectionMigrationScenario() *ConnectionMigrationScenario {
	return &ConnectionMigrationScenario{AbstractScenario{"connection_migration", 1, false, nil}}
}
func (s *ConnectionMigrationScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)
	connAgents := s.CompleteHandshake(conn, trace, CM_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C // Wait some time before migrating

	connAgents.Get("SocketAgent").Stop()
	connAgents.Get("SendingAgent").Stop()
	connAgents.Get("SocketAgent").Join()
	connAgents.Get("SendingAgent").Join()

	newUdpConn, err := qt.EstablishUDPConnection(conn.Host)
	if err != nil {
		trace.ErrorCode = CM_UDPConnectionFailed
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = newUdpConn

	connAgents.Get("SocketAgent").Run(conn)
	connAgents.Get("SendingAgent").Run(conn)

	conn.EncryptionLevelsAvailable.Submit(qt.DirectionalEncryptionLevel{qt.EncryptionLevelHandshake, false})  // TODO: Find a way around this
	conn.EncryptionLevelsAvailable.Submit(qt.DirectionalEncryptionLevel{qt.EncryptionLevel1RTT, false})

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	conn.SendHTTPGETRequest(preferredUrl, 0)
	trace.ErrorCode = CM_HostDidNotMigrate // Assume it until proven wrong

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if trace.ErrorCode == CM_HostDidNotMigrate {
				trace.ErrorCode = CM_HostDidNotValidateNewPath
			}

			if fp, ok := p.(qt.Framer); ok && fp.Contains(qt.PathChallengeType) {
				trace.ErrorCode = 0
			}

			if conn.Streams.Get(0).ReadClosed {
				conn.CloseConnection(false, 0, "")
			}
		case <-s.Timeout().C:
			return
		}
	}
}
