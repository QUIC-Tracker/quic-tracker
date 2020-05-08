package scenarii

import (
	"bytes"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"math/rand"

	"time"
)

const (
	CM_TLSHandshakeFailed        = 1
	CM_UDPConnectionFailed       = 2
	CM_HostDidNotMigrate         = 3
	CM_HostDidNotValidateNewPath = 4
	CM_TooManyCIDs			 	 = 5
)

type ConnectionMigrationScenario struct {
	AbstractScenario
}

func NewConnectionMigrationScenario() *ConnectionMigrationScenario {
	return &ConnectionMigrationScenario{AbstractScenario{name: "connection_migration", version: 1}}
}
func (s *ConnectionMigrationScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, CM_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)
	t := time.NewTimer(3 * time.Second)

	scid := make([]byte, 8)
	var resetToken [16]byte
	rand.Read(scid)
	rand.Read(resetToken[:])
	conn.FrameQueue.Submit(qt.QueuedFrame{&qt.NewConnectionIdFrame{1, 0, uint8(len(scid)), scid, resetToken}, qt.EncryptionLevelBest})

	var ncid []byte
wait:
	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if fp, ok := p.(qt.Framer); ok && fp.Header().PacketType() == qt.ShortHeaderPacket && fp.Contains(qt.NewConnectionIdType) {
				ncids := fp.GetAll(qt.NewConnectionIdType)
				if len(ncids) > int(conn.TLSTPHandler.ActiveConnectionIdLimit) {
					trace.MarkError(CM_TooManyCIDs, "", p)
					return
				}
				ncid = ncids[0].(*qt.NewConnectionIdFrame).ConnectionId
			}
		case <-t.C:
			conn.IncomingPackets.Unregister(incPackets)
			incPackets = nil
			break wait
		}
	}

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

	incPackets = conn.IncomingPackets.RegisterNewChan(1000)

	responseChan := connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)
	trace.ErrorCode = CM_HostDidNotMigrate // Assume it until proven wrong

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if trace.ErrorCode == CM_HostDidNotMigrate {
				trace.ErrorCode = CM_HostDidNotValidateNewPath
				if bytes.Equal(p.Header().DestinationConnectionID(), scid) && ncid != nil {
					conn.SourceCID = scid
					conn.DestinationCID = ncid
				}
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
