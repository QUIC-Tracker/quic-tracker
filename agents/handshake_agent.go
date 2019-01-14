package agents

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/dustin/go-broadcast"
	"strings"
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
	HandshakeStatus  broadcast.Broadcaster //type: HandshakeStatus
	sendInitial		 chan bool
	receivedRetry    bool
}

func (a *HandshakeAgent) Run(conn *Connection) {
	a.Init("HandshakeAgent", conn.OriginalDestinationCID)
	a.HandshakeStatus = broadcast.NewBroadcaster(10)
	a.sendInitial = make(chan bool, 1)

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

	outPackets := make(chan interface{}, 1000)
	conn.OutgoingPackets.Register(outPackets)

	tlsStatus := make(chan interface{}, 10)
	a.TLSAgent.TLSStatus.Register(tlsStatus)

	socketStatus := make(chan interface{}, 10)
	a.SocketAgent.SocketStatus.Register(socketStatus)

	firstInitialReceived := false
	tlsCompleted := false
	var tlsPacket Packet

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case <-a.sendInitial:
				a.Logger.Println("Sending first Initial packet")
				conn.SendPacket(conn.GetInitialPacket(), EncryptionLevelInitial)
			case p := <-incPackets:
				switch p := p.(type) {
				case *VersionNegotiationPacket:
					err := conn.ProcessVersionNegotation(p)
					if err != nil {
						a.HandshakeStatus.Submit(HandshakeStatus{false, p, err})
						return
					}
					conn.SendPacket(conn.GetInitialPacket(), EncryptionLevelInitial)
				case *RetryPacket:
					if bytes.Equal(conn.DestinationCID, p.OriginalDestinationCID) && !a.receivedRetry {  // TODO: Check the original_connection_id TP too
						a.receivedRetry = true
						conn.DestinationCID = p.Header().(*LongHeader).SourceCID
						conn.TransitionTo(QuicVersion, QuicALPNToken)
						conn.Token = p.RetryToken
						a.TLSAgent.Stop()
						a.TLSAgent.Join()
						a.TLSAgent.Run(conn)
						a.TLSAgent.TLSStatus.Register(tlsStatus)
						conn.SendPacket(conn.GetInitialPacket(), EncryptionLevelInitial)
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
				default:
					a.HandshakeStatus.Submit(HandshakeStatus{false, p.(Packet), errors.New("received incorrect packet type during handshake")})
				}
			case p := <-outPackets:
				if !tlsCompleted {
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
					a.HandshakeStatus.Submit(HandshakeStatus{s.Completed, s.Packet, s.Error})
				}
				tlsCompleted = s.Completed
				tlsPacket = s.Packet
			case i := <-socketStatus:
				if strings.Contains(i.(error).Error(), "connection refused") {
					a.HandshakeStatus.Submit(HandshakeStatus{false, nil , i.(error)})
				}
			case <-a.close:
				return
			}
		}
	}()

	status := make(chan interface{}, 1)
	a.HandshakeStatus.Register(status)

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
