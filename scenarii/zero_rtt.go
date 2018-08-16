package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"

	"time"
	"github.com/QUIC-Tracker/quic-tracker/agents"
)

const (
	ZR_TLSHandshakeFailed           = 1
	ZR_NoResumptionSecret           = 2
	ZR_ZeroRTTFailed                = 3
	ZR_DidntReceiveTheRequestedData = 4
)

type ZeroRTTScenario struct {
	AbstractScenario
}

func NewZeroRTTScenario() *ZeroRTTScenario {
	return &ZeroRTTScenario{AbstractScenario{"zero_rtt", 1, false, nil}}
}
func (s *ZeroRTTScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, ZR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	select {
	case <-incPackets:
		if len(conn.Tls.ResumptionTicket()) > 0 {
			break
		}
	case <-s.Timeout().C:
		trace.MarkError(ZR_NoResumptionSecret, "", nil)
		connAgents.CloseConnection(false, 0, "")
		return
	}
	connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C

	resumptionTicket := conn.Tls.ResumptionTicket()
	rh, sh := conn.ReceivedPacketHandler, conn.SentPacketHandler

	var err error
	conn, err = qt.NewDefaultConnection(conn.Host.String(), conn.ServerName, resumptionTicket, s.ipv6)
	conn.ReceivedPacketHandler = rh
	conn.SentPacketHandler = sh
	if err != nil {
		trace.MarkError(ZR_ZeroRTTFailed, err.Error(), nil)
		return
	}

	connAgents = agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	connAgents.Get("RecoveryAgent").Stop()
	connAgents.Get("RecoveryAgent").Join()
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	defer connAgents.CloseConnection(false, 0, "")

	incPackets = make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	encryptionLevelsAvailable := make(chan interface{}, 10)
	conn.EncryptionLevelsAvailable.Register(encryptionLevelsAvailable)

	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)
	handshakeAgent.InitiateHandshake()

forLoop:
	for {
		select {
		case i := <-encryptionLevelsAvailable:
			eL := i.(qt.DirectionalEncryptionLevel)
			if eL.EncryptionLevel == qt.EncryptionLevel0RTT && !eL.Read {
				break forLoop
			}
		case <-s.Timeout().C:
			trace.ErrorCode = ZR_ZeroRTTFailed
			trace.Results["error"] = "0-RTT encryption was not available after feeding in the ticket"
			return
		}
	}
	// TODO: Handle stateless connection

	conn.SendHTTPGETRequest(preferredUrl, 0)  // TODO: Verify that this get sent in a 0-RTT packet

	trace.ErrorCode = ZR_DidntReceiveTheRequestedData
	for {
		select {
			case <-incPackets:
				if conn.Streams.Get(0).ReadClosed {
					trace.ErrorCode = 0
					return
				}
			case <-s.Timeout().C:
				return
		}
	}
}
