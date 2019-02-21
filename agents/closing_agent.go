package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"time"
)

// The ClosingAgent is responsible for keeping track of events that can close the connection, such as the idle timeout.
// It can queue an (CONNECTION|APPLICATION)_CLOSE frame and wait for it to be sent out.
type ClosingAgent struct {
	BaseAgent
	closing      bool
	conn         *Connection
	IdleDuration time.Duration
	IdleTimeout  *time.Timer
}

func (a *ClosingAgent) Run(conn *Connection) {
	a.Init("ClosingAgent", conn.OriginalDestinationCID)
	a.conn = conn
	a.IdleDuration = time.Duration(a.conn.TLSTPHandler.IdleTimeout) * time.Second
	a.IdleTimeout = time.NewTimer(a.IdleDuration)

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)
	outgoingPackets := conn.OutgoingPackets.RegisterNewChan(1000)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		defer close(a.conn.ConnectionClosed)

		for {
			select {
			case <-incomingPackets:
				a.IdleTimeout.Reset(a.IdleDuration)
			case i := <-outgoingPackets:
				switch p := i.(type) {
				case Framer:
					if a.closing && (p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType)) {
						return
					}
				}
				if p := i.(Packet); p.ShouldBeAcknowledged() {
					a.IdleTimeout.Reset(a.IdleDuration)
				}
			case <-a.IdleTimeout.C:
				a.closing = true
				a.Logger.Printf("Idle timeout of %v reached, closing\n", a.IdleDuration.String())
				return
			}
		}
	}()
}

func (a *ClosingAgent) Close(quicLayer bool, errorCode uint16, reasonPhrase string) {
	if !a.closing {
		a.closing = true
		a.conn.CloseConnection(quicLayer, errorCode, reasonPhrase)
	}
}
