package agents

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"strings"
	"time"
)

type HandshakeStatus struct {
	Completed bool
	Packet
	Error     error
}

func (s HandshakeStatus) String() string {
	return fmt.Sprintf("HandshakeStatus{Completed=%t, Error=%s}", s.Completed, s.Error)
}

// The HandshakeAgent is responsible for initiating the QUIC handshake and respond to the version negotiation process if
// the server requires it. It reports the status of the handshake through the HandshakeStatus attribute. The status
// should only be published once, reporting a failure or a success.
type HandshakeAgent struct {
	BaseAgent
	TLSAgent         *TLSAgent
	SocketAgent      *SocketAgent
	HandshakeStatus  Broadcaster //type: HandshakeStatus
	IgnoreRetry 	 bool
	DontDropKeys     bool
	sendInitial		 chan bool
	receivedRetry    bool
	retrySource      ConnectionID
}

func (a *HandshakeAgent) Run(conn *Connection) {
	a.Init("HandshakeAgent", conn.OriginalDestinationCID)
	a.HandshakeStatus = NewBroadcaster(10)
	a.sendInitial = make(chan bool, 1)

	incPackets := conn.IncomingPackets.RegisterNewChan(1000)
	outPackets := conn.OutgoingPackets.RegisterNewChan(1000)
	tlsStatus := a.TLSAgent.TLSStatus.RegisterNewChan(10)
	socketStatus := a.SocketAgent.SocketStatus.RegisterNewChan(10)

	firstInitialReceived := false
	tlsCompleted := false
	pingTimer := time.NewTimer(0)
	var tlsPacket Packet

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case <-a.sendInitial:
				a.Logger.Println("Sending first Initial packet")
				conn.SendPacket.Submit(PacketToSend{Packet: conn.GetInitialPacket(), EncryptionLevel: EncryptionLevelInitial})
			case p := <-incPackets:
				switch p := p.(type) {
				case *VersionNegotiationPacket:
					err := conn.ProcessVersionNegotation(p)
					if err != nil {
						a.HandshakeStatus.Submit(HandshakeStatus{false, p, err})
						return
					}
					close(conn.ConnectionRestart)
				case *RetryPacket:
					// TODO: Validate this, https://tools.ietf.org/html/draft-ietf-quic-tls-27#section-5.8
					if !a.IgnoreRetry && !a.receivedRetry {
						a.Logger.Println("A Retry packet was received, restarting the connection")
						a.receivedRetry = true
						conn.DestinationCID = p.Header().(*LongHeader).SourceCID
						a.retrySource = p.Header().(*LongHeader).SourceCID
						tlsTP, alpn := conn.TLSTPHandler, conn.ALPN
						conn.TransitionTo(QuicVersion, alpn)
						conn.TLSTPHandler = tlsTP
						conn.Token = p.RetryToken
						close(conn.ConnectionRestart)
					}
				case Framer:
					if p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType) {
						a.Logger.Println("The connection was closed before the handshake completed")
						a.HandshakeStatus.Submit(HandshakeStatus{false, p, errors.New("the connection was closed before the handshake completed")})
						return
					}
					if _, ok := p.(*InitialPacket); ok && !firstInitialReceived {
						firstInitialReceived = true
						conn.DestinationCID = p.Header().(*LongHeader).SourceCID
						a.Logger.Printf("Received first Initial packet from server, switching DCID to %s\n", hex.EncodeToString(conn.DestinationCID))
					}
					if p.Contains(HandshakeDoneType) {
						a.HandshakeStatus.Submit(HandshakeStatus{true, tlsPacket, nil})
						conn.IncomingPackets.Unregister(incPackets)
						if !a.DontDropKeys {
							conn.EncryptionLevels.Submit(DirectionalEncryptionLevel{EncryptionLevel: EncryptionLevelInitial, Available: false})
							conn.EncryptionLevels.Submit(DirectionalEncryptionLevel{EncryptionLevel: EncryptionLevelHandshake, Available: false})
							// TODO: Drop crypto contexts accordingly
						}
					}
				default:
					a.HandshakeStatus.Submit(HandshakeStatus{false, p.(Packet), errors.New("received incorrect packet type during handshake")})
				}
				pingTimer.Reset(time.Duration(conn.SmoothedRTT + conn.RTTVar) * time.Microsecond)
			case p := <-outPackets:
				if !tlsCompleted || conn.Version >= 0xff000019 {
					break
				}
				switch p := p.(type) {
				case *HandshakePacket:
					for _, f := range p.GetAll(CryptoType) {
						cf := f.(*CryptoFrame)
						if cf.CryptoData[0] == 0x14 { // TLS Finished
							a.HandshakeStatus.Submit(HandshakeStatus{true, tlsPacket, nil})
							conn.IncomingPackets.Unregister(incPackets)
							conn.OutgoingPackets.Unregister(outPackets)
							return
						}
					}
				}
			case i := <-tlsStatus:
				s := i.(TLSStatus)
				if s.Error != nil {
					if s.Completed {
						if !bytes.Equal(conn.TLSTPHandler.ReceivedParameters.OriginalDestinationConnectionId, conn.OriginalDestinationCID) {
							a.Logger.Println("The server included an invalid original_destination_connection_id")
							s.Completed = false
							s.Error = errors.New(fmt.Sprint("invalid original_destination_connection_id"))
						} else if a.receivedRetry {
							if !bytes.Equal(conn.TLSTPHandler.ReceivedParameters.RetrySourceConnectionId, a.retrySource) {
								a.Logger.Println("The server include an invalid retry_source_connection_id after sending a Retry")
								s.Completed = false
								s.Error = errors.New(fmt.Sprint("invalid retry_source_connection_id"))
							}
						} else {
							if conn.TLSTPHandler.ReceivedParameters.RetrySourceConnectionId != nil {
								a.Logger.Println("The server included a retry_source_connection_id but did not send a Retry")
								s.Completed = false
								s.Error = errors.New(fmt.Sprint("invalid retry_source_connection_id"))
							}
						}
					}
					a.HandshakeStatus.Submit(HandshakeStatus{s.Completed, s.Packet, s.Error})
				}
				tlsCompleted = s.Completed
				tlsPacket = s.Packet
			case i := <-socketStatus:
				if strings.Contains(i.(error).Error(), "connection refused") {
					a.HandshakeStatus.Submit(HandshakeStatus{false, nil , i.(error)})
					return
				}
			case <-pingTimer.C:
				if firstInitialReceived {
					conn.PreparePacket.Submit(EncryptionLevelBest)
				}
			case <-conn.ConnectionRestarted:
				incPackets = conn.IncomingPackets.RegisterNewChan(1000)
				outPackets = conn.OutgoingPackets.RegisterNewChan(1000)
				tlsStatus = a.TLSAgent.TLSStatus.RegisterNewChan(10)
				socketStatus = a.SocketAgent.SocketStatus.RegisterNewChan(10)
				conn.ConnectionRestarted = make(chan bool, 1)
				conn.SendPacket.Submit(PacketToSend{Packet: conn.GetInitialPacket(), EncryptionLevel: EncryptionLevelInitial})
			case <-a.close:
				return
			}
		}
	}()

	status := a.HandshakeStatus.RegisterNewChan(1)

	go func() {
		for {
			select {
			case i := <-status:
				a.Logger.Printf("New status %s\n", i.(HandshakeStatus).String())
			case <-a.close:
				return
			}
		}
	}()
}

func (a *HandshakeAgent) InitiateHandshake() {
	a.sendInitial <- true
}
