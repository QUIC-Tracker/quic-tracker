package agents

import . "github.com/mpiraux/master-thesis"

type ClosingAgent struct {
	BaseAgent
	QuicLayer bool
	ErrorCode uint16
	ReasonPhrase string
}

func (a *ClosingAgent) Run (conn *Connection) {
	a.Init("ClosingAgent", conn.SourceCID)

	outgoingPackets := make(chan interface{}, 1000)
	conn.OutgoingPackets.Register(outgoingPackets)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)

		conn.CloseConnection(a.QuicLayer, a.ErrorCode, a.ReasonPhrase)
		for {
			switch p := (<-outgoingPackets).(type) {
			case Framer:
				if p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType) {
					return
				}
			}
		}
	}()
}
