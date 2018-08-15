package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
)

type AckAgent struct {
	BaseAgent
	DisableAcks         bool
	DisablePathResponse bool
}

func (a *AckAgent) Run(conn *Connection) {
	a.Init("AckAgent", conn.SourceCID)

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-incomingPackets:
				p := i.(Packet)
				if p.PNSpace() != PNSpaceNoSpace {
					pn := p.Header().PacketNumber()
					for _, number := range conn.AckQueue[p.PNSpace()] {
						if number == pn {
							a.Logger.Printf("Received duplicate packet number %d in PN space %s\n", pn, p.PNSpace().String())
							// TODO: This should be flagged somewhere
						}
					}

					conn.AckQueue[p.PNSpace()] = append(conn.AckQueue[p.PNSpace()], pn)

					if framePacket, ok := p.(Framer); ok {
						if pathChallenge := framePacket.GetFirst(PathChallengeType); !a.DisablePathResponse && pathChallenge != nil {
							conn.FrameQueue.Submit(QueuedFrame{&PathResponse{pathChallenge.(*PathChallenge).Data}, p.EncryptionLevel()})
						}
					}

					if !a.DisableAcks && p.ShouldBeAcknowledged()  {
						conn.FrameQueue.Submit(QueuedFrame{conn.GetAckFrame(p.PNSpace()), p.EncryptionLevel()})
					}
				}
			case <-a.close:
				return
			}
		}
	}()
}
