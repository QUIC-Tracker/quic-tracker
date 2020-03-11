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
	return &ConnectionMigrationScenario{AbstractScenario{name: "connection_migration", version: 1}}
}
func (s *ConnectionMigrationScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	conn.TLSTPHandler.ActiveConnectionIdLimit = 0
	connAgents := s.CompleteHandshake(conn, trace, CM_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C // Wait some time before migrating

	connAgents.Stop("SocketAgent", "SendingAgent")

	newUdpConn, err := qt.EstablishUDPConnection(conn.Host)
	if err != nil {
		trace.ErrorCode = CM_UDPConnectionFailed
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = newUdpConn

	connAgents.Get("SocketAgent").Run(conn)
	connAgents.Get("SendingAgent").Run(conn)
	conn.EncryptionLevels.Submit(qt.DirectionalEncryptionLevel{EncryptionLevel: qt.EncryptionLevel1RTT, Available: true})

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	responseChan := connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)
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
		case <-responseChan:
			s.Finished()
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
