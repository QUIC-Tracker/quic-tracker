package agents

import (
	. "github.com/mpiraux/master-thesis"
	"github.com/dustin/go-broadcast"
	"errors"
	"encoding/hex"
	"fmt"
)

type HandshakeStatus struct {
	Completed bool
	Packet
	Error     error
}

func (s HandshakeStatus) String() string {
	return fmt.Sprintf("HandshakeStatus{Completed=%t, Error=%s}", s.Completed, s.Error)
}

type HandshakeAgent struct {
	BaseAgent
	conn            *Connection
	TLSAgent        *TLSAgent
	HandshakeStatus broadcast.Broadcaster //type: HandshakeStatus
	ResumptionToken []byte                // If present, the agent will initiate a 0-RTT connection
}

func (a *HandshakeAgent) Run(conn *Connection) {
	a.Init("HandshakeAgent", conn.SourceCID)
	a.HandshakeStatus = broadcast.NewBroadcaster(10)
	a.conn = conn
}

func (a *HandshakeAgent) InitiateHandshake() {
	incPackets := make(chan interface{}, 1000)
	a.conn.IncomingPackets.Register(incPackets)

	tlsStatus := make(chan interface{}, 10)
	a.TLSAgent.TLSStatus.Register(tlsStatus)

	a.conn.SendPacket(a.conn.GetInitialPacket(), EncryptionLevelInitial)
	firstInitialReceived := false

	go func() {
		for {
			select {
			case p := <-incPackets:
				switch p := p.(type) {
				case *VersionNegotationPacket:
					err := a.conn.ProcessVersionNegotation(p)
					if err != nil {
						a.HandshakeStatus.Submit(HandshakeStatus{false, p, err})
						return
					}
					a.conn.SendPacket(a.conn.GetInitialPacket(), EncryptionLevelInitial)
				case *RetryPacket:
					// TODO: Reimplement stateless connection
					panic("not implemented")

				case Framer:
					if p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType) {
						a.Logger.Println("The connection was closed before the handshake completed")
						a.HandshakeStatus.Submit(HandshakeStatus{false, p, errors.New("the connection was closed before the handshake completed")})
						return
					}
					if _, ok := p.(*InitialPacket); ok && !firstInitialReceived {
						firstInitialReceived = true
						a.conn.DestinationCID = p.Header().(*LongHeader).SourceCID
						a.Logger.Printf("Received first Initial packet from server, switching DCID to %s\n", hex.EncodeToString(a.conn.DestinationCID))
					}
				default:
					a.HandshakeStatus.Submit(HandshakeStatus{false, p.(Packet), errors.New("received incorrect packet type during handshake")})
				}
			case i := <-tlsStatus:
				s := i.(TLSStatus)
				a.HandshakeStatus.Submit(HandshakeStatus{s.Completed, s.Packet, s.Error})
				return
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
