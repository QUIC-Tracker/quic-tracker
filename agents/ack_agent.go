package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
)

// The AckAgent is in charge of queuing ACK frames in response to receiving packets that need to be acknowledged as well
// as answering to PATH_CHALLENGE frames. Both can be disabled independently for a finer control on its behaviour.
type AckAgent struct {
	BaseAgent
	DisableAcks 		map[PNSpace]bool
	TotalDataAcked 	    map[PNSpace]uint64
	DisablePathResponse bool
}

func (a *AckAgent) Run(conn *Connection) {
	a.Init("AckAgent", conn.SourceCID)
	a.DisableAcks = make(map[PNSpace]bool)
	a.TotalDataAcked = make(map[PNSpace]uint64)

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

					if !a.DisableAcks[p.PNSpace()] && p.ShouldBeAcknowledged()  {
						conn.FrameQueue.Submit(QueuedFrame{conn.GetAckFrame(p.PNSpace()), p.EncryptionLevel()})
						a.TotalDataAcked[p.PNSpace()] += uint64(len(p.Encode(p.EncodePayload())))
					}
				}
			case <-a.close:
				return
			}
		}
	}()
}
