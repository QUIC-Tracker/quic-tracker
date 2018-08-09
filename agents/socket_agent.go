package agents

import m "github.com/mpiraux/master-thesis"

type SocketAgent struct {
	BaseAgent
	TotalDataReceived int
	DatagramsReceived int
}

func (a *SocketAgent) Run(conn *m.Connection) {
	a.Init("SocketAgent", conn.SourceCID)
	recChan := make(chan []byte)

	go func() {
		for {
			recBuf := make([]byte, m.MaxUDPPayloadSize)
			i, err := conn.UdpConnection.Read(recBuf)
			if err != nil {
				a.Logger.Println("Closing UDP socket because of error", err.Error())
				close(recChan)
				break
			}
			a.TotalDataReceived += i
			a.DatagramsReceived += 1
			a.Logger.Printf("Received %d bytes from UDP socket\n", i)
			payload := make([]byte, i)
			copy(payload, recBuf[:i])
			recChan <- payload
		}
	}()

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case p, open := <-recChan:
				if !open {
					return
				}

				conn.IncomingPayloads.Submit(p)
			case <-a.close:
				conn.UdpConnection.Close()
				// TODO: Close this agent gracefully
				return
			}
		}
	}()
}
