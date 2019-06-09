package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"time"
)

// The AckAgent is in charge of queuing ACK frames in response to receiving packets that need to be acknowledged as well
// as answering to PATH_CHALLENGE frames. Both can be disabled independently for a finer control on its behaviour.
type AckAgent struct {
	FrameProducingAgent
	DisableAcks         map[PNSpace]bool
	TotalDataAcked      map[PNSpace]uint64
	DisablePathResponse bool
}

func (a *AckAgent) Run(conn *Connection) {
	a.BaseAgent.Init("AckAgent", conn.OriginalDestinationCID)
	a.FrameProducingAgent.InitFPA(conn)
	if a.DisableAcks == nil {
		a.DisableAcks = make(map[PNSpace]bool)
	}
	a.TotalDataAcked = make(map[PNSpace]uint64)

	recvdTimestamps := make(map[PNSpace]map[PacketNumber]time.Time)
	for _, space := range []PNSpace{PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData} {
		recvdTimestamps[space] = make(map[PacketNumber]time.Time)
	}
	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

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
							// TODO: This should be flagged somewhere, and placed in a more general ErrorAgent
						}
					}

					conn.AckQueue[p.PNSpace()] = append(conn.AckQueue[p.PNSpace()], pn)
					recvdTimestamps[p.PNSpace()][p.Header().PacketNumber()] = p.ReceiveContext().Timestamp

					if framePacket, ok := p.(Framer); ok {
						if pathChallenge := framePacket.GetFirst(PathChallengeType); !a.DisablePathResponse && pathChallenge != nil {
							conn.FrameQueue.Submit(QueuedFrame{&PathResponse{pathChallenge.(*PathChallenge).Data}, p.EncryptionLevel()})
						}
					}

					if !a.DisableAcks[p.PNSpace()] && p.ShouldBeAcknowledged() {
						a.conn.PreparePacket.Submit(p.EncryptionLevel())
						a.TotalDataAcked[p.PNSpace()] += uint64(len(p.Encode(p.EncodePayload()))) // TODO: See following todo
					}
				}
			case args := <-a.requestFrame: // TODO: Keep track of the ACKs and their packet to shorten the ack blocks once received by the peer
				pnSpace := EncryptionLevelToPNSpace[args.level]
				if a.DisableAcks[pnSpace] || args.level == EncryptionLevelBest || args.level == EncryptionLevelBestAppData || args.level == EncryptionLevel0RTT {
					a.frames <- nil
					break
				}
				f := conn.GetAckFrame(pnSpace)
				if f != nil {
					lRTimestamp, ok := recvdTimestamps[pnSpace][f.LargestAcknowledged]
					if ok {
						f.AckDelay = uint64((time.Now().Sub(lRTimestamp).Round(time.Microsecond) / time.Microsecond) >> conn.TLSTPHandler.AckDelayExponent)
					}
					if args.availableSpace >= int(f.FrameLength()) {
						a.frames <- []Frame{f}
					} else {
						a.conn.PreparePacket.Submit(args.level)
						a.frames <- nil
					}
				} else {
					a.frames <- nil
				}
			case <-a.close:
				return
			}
		}
	}()
}
