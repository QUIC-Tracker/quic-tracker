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

	resumptionTicket := make(chan interface{}, 10)
	connAgents.Get("TLSAgent").(*agents.TLSAgent).ResumptionTicket.Register(resumptionTicket)

	var ticket []byte
forLoop1:
	for {
		select {
		case i := <-resumptionTicket:
			ticket = i.([]byte)
			break forLoop1
		case <-s.Timeout().C:
			trace.MarkError(ZR_NoResumptionSecret, "", nil)
			connAgents.CloseConnection(false, 0, "")
			return
		}
	}
	connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C

	rh, sh, token := conn.ReceivedPacketHandler, conn.SentPacketHandler, conn.Token

	var err error
	conn, err = qt.NewDefaultConnection(conn.Host.String(), conn.ServerName, ticket, s.ipv6)
	conn.ReceivedPacketHandler = rh
	conn.SentPacketHandler = sh
	conn.Token = token
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
	defer trace.Complete(conn)

	incPackets = make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	encryptionLevelsAvailable := make(chan interface{}, 10)
	conn.EncryptionLevelsAvailable.Register(encryptionLevelsAvailable)

	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)
	handshakeAgent.InitiateHandshake()

	if !s.waitFor0RTT(trace, encryptionLevelsAvailable) {
		return
	}

	// TODO: Handle stateless connection

	conn.SendHTTPGETRequest(preferredUrl, 0)  // TODO: Verify that this get sent in a 0-RTT packet

	trace.ErrorCode = ZR_DidntReceiveTheRequestedData
	for {
		select {
			case i := <-incPackets:
				switch i.(type) {
				case *qt.RetryPacket:
					if !s.waitFor0RTT(trace, encryptionLevelsAvailable) {
						return
					}
					conn.SendHTTPGETRequest(preferredUrl, 0)
				}
				if conn.Streams.Get(0).ReadClosed {
					trace.ErrorCode = 0
				}
			case <-s.Timeout().C:
				return
		}
	}
}

func (s *ZeroRTTScenario) waitFor0RTT(trace *qt.Trace, encryptionLevelsAvailable chan interface{}) bool {
	for {
		select {
		case i := <-encryptionLevelsAvailable:
			eL := i.(qt.DirectionalEncryptionLevel)
			if eL.EncryptionLevel == qt.EncryptionLevel0RTT && !eL.Read {
				return true
			}
		case <-s.Timeout().C:
			trace.ErrorCode = ZR_ZeroRTTFailed
			trace.Results["error"] = "0-RTT encryption was not available after feeding in the ticket"
			return false
		}
	}
}