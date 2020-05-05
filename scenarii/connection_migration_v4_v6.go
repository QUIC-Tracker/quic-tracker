package scenarii

import (
	"bytes"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"math/rand"
	"net"
	"time"
)

const (
	CM46_TLSHandshakeFailed        = 1
	CM46_UDPConnectionFailed       = 2
	CM46_HostDidNotMigrate         = 3
	CM46_HostDidNotValidateNewPath = 4
	CM46_NoNewCIDReceived		   = 5
	CM46_NoNewCIDUsed			   = 6
	CM46_MigrationIsDisabled 	   = 7
	CM46_NoCIDAllowed	     	   = 8
)


type ConnectionMigrationv4v6Scenario struct {
	AbstractScenario
}

func NewConnectionMigrationv4v6Scenario() *ConnectionMigrationv4v6Scenario {
	return &ConnectionMigrationv4v6Scenario{AbstractScenario{name: "connection_migration_v4_v6", version: 1}}
}
func (s *ConnectionMigrationv4v6Scenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	connAgents := s.CompleteHandshake(conn, trace, CM46_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.DisableMigration {
		trace.ErrorCode = CM46_MigrationIsDisabled
		return
	}

	if conn.TLSTPHandler.ReceivedParameters.ActiveConnectionIdLimit < 0 {
		trace.ErrorCode = CM46_NoCIDAllowed
		return
	}

	scid := make([]byte, 8)
	var resetToken [16]byte
	rand.Read(scid)
	rand.Read(resetToken[:])
	conn.FrameQueue.Submit(qt.QueuedFrame{&qt.NewConnectionIdFrame{1, 0, uint8(len(scid)), scid, resetToken}, qt.EncryptionLevelBest})
	firstFlightTimer := time.NewTimer(3 * time.Second)

	var ncid qt.ConnectionID
firstFlight:
	for {
		select {
		case i := <-incPackets:
			switch p := i.(type) {
			case *qt.ProtectedPacket:
				if p.Contains(qt.NewConnectionIdType) {
					ncid = p.GetFirst(qt.NewConnectionIdType).(*qt.NewConnectionIdFrame).ConnectionId
					break firstFlight
				}
			}
		case <-firstFlightTimer.C:
			trace.ErrorCode = CM46_NoNewCIDReceived
			return
		}
	}
	<-firstFlightTimer.C

	connAgents.Stop("SocketAgent", "SendingAgent")
	conn.DestinationCID = ncid
	conn.SourceCID = scid

	v6Addr, err := net.ResolveUDPAddr("udp6", trace.Host)
	if err != nil {
		trace.ErrorCode = CM46_UDPConnectionFailed
		trace.Results["ResolveUDPAddr"] = err.Error()
		return
	}
	udpConn, err := qt.EstablishUDPConnection(v6Addr)
	if err != nil {
		trace.ErrorCode = CM46_UDPConnectionFailed
		trace.Results["EstablishUDPConnection"] = err.Error()
		return
	}

	conn.UdpConnection.Close()
	conn.UdpConnection = udpConn

	connAgents.Get("SocketAgent").Run(conn)
	connAgents.Get("SendingAgent").Run(conn)
	conn.EncryptionLevels.Submit(qt.DirectionalEncryptionLevel{EncryptionLevel: qt.EncryptionLevel1RTT, Available: true})

	incPackets = conn.IncomingPackets.RegisterNewChan(1000)

	responseChan := connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)
	trace.ErrorCode = CM46_HostDidNotMigrate // Assume it until proven wrong

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if trace.ErrorCode == CM46_HostDidNotMigrate {
				trace.ErrorCode = CM46_HostDidNotValidateNewPath
			}

			if fp, ok := p.(qt.Framer); ok && fp.Contains(qt.PathChallengeType) && trace.ErrorCode == CM46_HostDidNotValidateNewPath {
				trace.ErrorCode = CM46_NoNewCIDUsed
			}

			if bytes.Equal(p.Header().DestinationConnectionID(), scid) && trace.ErrorCode == CM46_NoNewCIDUsed {
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
