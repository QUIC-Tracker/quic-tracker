package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"strings"

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
	return &ZeroRTTScenario{AbstractScenario{name: "zero_rtt", version: 1}}
}
func (s *ZeroRTTScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, ZR_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	resumptionTicket := connAgents.Get("TLSAgent").(*agents.TLSAgent).ResumptionTicket.RegisterNewChan(10)

	ticket := conn.Tls.ResumptionTicket()

	if len(ticket) <= 0 {
	getTicket:
		for {
			select {
			case i := <-resumptionTicket:
				ticket = i.([]byte)
				break getTicket
			case <-conn.ConnectionClosed:
				trace.MarkError(ZR_NoResumptionSecret, "", nil)
				connAgents.CloseConnection(false, 0, "")
				return
			case <-s.Timeout():
				trace.MarkError(ZR_NoResumptionSecret, "", nil)
				connAgents.CloseConnection(false, 0, "")
				return
			}
		}
	}
	connAgents.CloseConnection(false, 0, "")

	<-time.NewTimer(3 * time.Second).C

	rh, sh, token := conn.ReceivedPacketHandler, conn.SentPacketHandler, conn.Token

	var err error
	conn, err = qt.NewDefaultConnection(conn.Host.String(), conn.ServerName, ticket, s.ipv6, "hq", strings.Contains(conn.ALPN, "h3"))
	conn.ReceivedPacketHandler = rh
	conn.SentPacketHandler = sh
	conn.Token = token
	if err != nil {
		trace.MarkError(ZR_ZeroRTTFailed, err.Error(), nil)
		return
	}

	connAgents = agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	connAgents.Stop("RecoveryAgent")
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: connAgents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: connAgents.Get("SocketAgent").(*agents.SocketAgent)}
	connAgents.Add(handshakeAgent)
	connAgents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = connAgents.GetFrameProducingAgents()
	defer connAgents.CloseConnection(false, 0, "")
	defer trace.Complete(conn)

	incPackets = conn.IncomingPackets.RegisterNewChan(1000)
	encryptionLevelsAvailable := conn.EncryptionLevels.RegisterNewChan(10)

	responseChan := connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil) // TODO: Verify that this get effectively sent in a 0-RTT packet
	handshakeAgent.InitiateHandshake() // TODO: Handle stateless connection

	if !s.waitFor0RTT(conn, trace, encryptionLevelsAvailable) {
		return
	}

	trace.ErrorCode = ZR_DidntReceiveTheRequestedData
	for {
		select {
			case i := <-incPackets:
				switch i.(type) {
				case *qt.RetryPacket:
					if !s.waitFor0RTT(conn, trace, encryptionLevelsAvailable) {
						return
					}
					responseChan = connAgents.AddHTTPAgent().SendRequest(preferredPath, "GET", trace.Host, nil)
				}
			case <-responseChan:
				trace.ErrorCode = 0
			case <-conn.ConnectionClosed:
				return
			case <-s.Timeout():
				return
		}
	}
}

func (s *ZeroRTTScenario) waitFor0RTT(conn *qt.Connection, trace *qt.Trace, encryptionLevelsAvailable chan interface{}) bool {
	for {
		select {
		case i := <-encryptionLevelsAvailable:
			eL := i.(qt.DirectionalEncryptionLevel)
			if eL.EncryptionLevel == qt.EncryptionLevel0RTT && !eL.Read {
				return true
			}
		case <-conn.ConnectionClosed:
			trace.ErrorCode = ZR_ZeroRTTFailed
			trace.Results["error"] = "0-RTT encryption was not available after feeding in the ticket"
			return false
		case <-s.Timeout():
			trace.ErrorCode = ZR_ZeroRTTFailed
			trace.Results["error"] = "0-RTT encryption was not available after feeding in the ticket"
			return false
		}
	}
}