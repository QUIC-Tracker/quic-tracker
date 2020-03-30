package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"github.com/QUIC-Tracker/quic-tracker/qlog/qt2qlog"
	"time"
)

// The RecoveryAgent is responsible of retransmitting frames that are part of packets considered as lost. It currently
// implements a simpler version of the Fast Retransmit mechanism and a linear Retransmission Timeout alarm.
type RecoveryAgent struct {
	BaseAgent
	conn                 *Connection
	retransmissionBuffer map[PNSpace]map[PacketNumber]RetransmittableFrames
	packetsSent 		 map[PNSpace]map[PacketNumber]bool
	TimerValue           time.Duration
}

func (a *RecoveryAgent) Run(conn *Connection) {
	a.Init("RecoveryAgent", conn.OriginalDestinationCID)
	a.conn = conn

	a.retransmissionBuffer = map[PNSpace]map[PacketNumber]RetransmittableFrames{
		PNSpaceInitial:   make(map[PacketNumber]RetransmittableFrames),
		PNSpaceHandshake: make(map[PacketNumber]RetransmittableFrames),
		PNSpaceAppData:   make(map[PacketNumber]RetransmittableFrames),
	}
	a.packetsSent = map[PNSpace]map[PacketNumber]bool{
		PNSpaceInitial:   make(map[PacketNumber]bool),
		PNSpaceHandshake: make(map[PacketNumber]bool),
		PNSpaceAppData:   make(map[PacketNumber]bool),
	}
	retransmissionTicker := time.NewTicker(100 * time.Millisecond)

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)
	outgoingPackets := conn.OutgoingPackets.RegisterNewChan(1000)
	eLAvailable := conn.EncryptionLevels.RegisterNewChan(10)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case <-retransmissionTicker.C:
				var batch RetransmitBatch
				for pnSpace, buffer := range a.retransmissionBuffer {
					for pn, v := range buffer {
						if time.Now().Sub(v.Timestamp) > a.TimerValue {
							a.conn.QLogEvents <- a.conn.QLogTrace.NewEvent(qlog.Categories.Recovery.Category, qlog.Categories.Recovery.PacketLost, qt2qlog.ConvertPacketLost(PNSpaceToPacketType[pnSpace], pn, v.Frames, "Linear timer"))
							batch = append(batch, v)
							delete(buffer, pn)
						}
					}
				}
				a.RetransmitBatch(batch)
			case i := <-incomingPackets:
				switch p := i.(type) {
				case Framer:
					ackFrames := append(p.GetAll(AckType), p.GetAll(AckECNType)...)
					for _, f := range ackFrames {
						var ack *AckFrame
						switch frame := f.(type) {
						case *AckFrame:
							a.Logger.Printf("Processing ACK frame in packet %s\n", p.ShortString())
							ack = frame
						case *AckECNFrame:
							a.Logger.Printf("Processing ACK_ECN frame in packet %s\n", p.ShortString())
							ack = &frame.AckFrame
						}
						if ack.LargestAcknowledged > conn.LargestPNsAcknowledged[p.PNSpace()] {
							conn.LargestPNsAcknowledged[p.PNSpace()] = ack.LargestAcknowledged
						}
						a.RetransmitBatch(a.ProcessAck(ack, p.PNSpace()))
					}
					if len(ackFrames) == 0 && p.PNSpace() == PNSpaceInitial { // Some implementations do not send ACK in this PNSpace
						a.Logger.Printf("Packet %s doesn't contain ACK frames, emptying the corresponding retransmission buffer anyway\n", p.ShortString())
						a.retransmissionBuffer[p.PNSpace()] = make(map[PacketNumber]RetransmittableFrames)
					}
					if p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType) {
						a.Stop()
					}
				case *RetryPacket:
					a.Logger.Println("Received a Retry packet, emptying Initial retransmit buffer")
					a.retransmissionBuffer[PNSpaceInitial] = make(map[PacketNumber]RetransmittableFrames)
				case *VersionNegotiationPacket:
					a.Logger.Println("Received a VN packet, emptying Initial retransmit buffer")
					a.retransmissionBuffer[PNSpaceInitial] = make(map[PacketNumber]RetransmittableFrames)
				}
			case i := <-outgoingPackets:
				switch p := i.(type) {
				case Framer:
					a.packetsSent[p.PNSpace()][p.Header().PacketNumber()] = true
					frames := p.GetRetransmittableFrames()
					if len(frames) > 0 {
						a.retransmissionBuffer[p.PNSpace()][p.Header().PacketNumber()] = *NewRetransmittableFrames(frames, p.EncryptionLevel())
					}
					if (p.Contains(ConnectionCloseType) || p.Contains(ApplicationCloseType)) && (len(a.retransmissionBuffer[PNSpaceInitial]) > 0 || len(a.retransmissionBuffer[PNSpaceHandshake]) > 0 || len(a.retransmissionBuffer[PNSpaceAppData]) > 0) {
						a.Logger.Println("Connection is closing, emptying retransmit buffers")
						a.retransmissionBuffer = map[PNSpace]map[PacketNumber]RetransmittableFrames{
							PNSpaceInitial:   make(map[PacketNumber]RetransmittableFrames),
							PNSpaceHandshake: make(map[PacketNumber]RetransmittableFrames),
							PNSpaceAppData:   make(map[PacketNumber]RetransmittableFrames),
						}
					}
				}
			case i := <-eLAvailable:
				eL := i.(DirectionalEncryptionLevel)
				if eL.Available && eL.EncryptionLevel == EncryptionLevel1RTT { // Handshake has completed, empty the retransmission buffers
					a.Logger.Println("Handshake has completed, emptying the two retransmission buffers")
					a.retransmissionBuffer[PNSpaceInitial] = make(map[PacketNumber]RetransmittableFrames)
					a.retransmissionBuffer[PNSpaceHandshake] = make(map[PacketNumber]RetransmittableFrames)
				}
				if !eL.Available && eL.EncryptionLevel == EncryptionLevelInitial {
					a.Logger.Println("Dropping Initial encryption level, emptying the retransmission buffer")
					a.retransmissionBuffer[PNSpaceInitial] = make(map[PacketNumber]RetransmittableFrames)
				}
				if !eL.Available && eL.EncryptionLevel == EncryptionLevelHandshake {
					a.Logger.Println("Dropping Handshake encryption level, emptying the retransmission buffer")
					a.retransmissionBuffer[PNSpaceHandshake] = make(map[PacketNumber]RetransmittableFrames)
				}
			case <-a.conn.ConnectionClosed:
				if len(a.retransmissionBuffer[PNSpaceInitial]) > 0 || len(a.retransmissionBuffer[PNSpaceHandshake]) > 0 || len(a.retransmissionBuffer[PNSpaceAppData]) > 0 {
					a.Logger.Println("Connection is closing, emptying retransmit buffers")
					a.retransmissionBuffer = map[PNSpace]map[PacketNumber]RetransmittableFrames{
						PNSpaceInitial:   make(map[PacketNumber]RetransmittableFrames),
						PNSpaceHandshake: make(map[PacketNumber]RetransmittableFrames),
						PNSpaceAppData:   make(map[PacketNumber]RetransmittableFrames),
					}
				}
			case <-a.close:
				return
			}
		}
	}()
}

func (a *RecoveryAgent) PacketAcknowledged(packet PacketNumber, space PNSpace) {
	if _, ok := a.packetsSent[space][packet]; !ok {
		a.Logger.Printf("Unknown packet %d (%s) was acknowledged\n", packet, space)
		return
	}
	buffer := a.retransmissionBuffer[space]
	delete(buffer, packet)
	a.conn.PacketAcknowledged.Submit(PacketAcknowledged{PacketNumber: packet, PNSpace: space})
}

func (a *RecoveryAgent) ProcessAck(ack *AckFrame, space PNSpace) RetransmitBatch { // Triggers fast retransmit and removes frames scheduled to be retransmitted
	threshold := uint64(1000)
	var frames RetransmitBatch
	buffer := a.retransmissionBuffer[space]
	currentPacketNumber := ack.LargestAcknowledged
	a.PacketAcknowledged(currentPacketNumber, space)
	for i := uint64(0); i < ack.AckRanges[0].AckRange && i < threshold; i++ {
		a.PacketAcknowledged(currentPacketNumber, space)
	}
	for _, ackBlock := range ack.AckRanges[1:] {
		for i := uint64(0); i <= ackBlock.Gap && i < threshold; i++ { // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			if f, ok := buffer[currentPacketNumber]; ok {
				frames = append(frames, f)
			}
			currentPacketNumber--
			delete(buffer, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.AckRange && i < threshold; i++ {
			a.PacketAcknowledged(currentPacketNumber, space)
		}
	}
	return frames
}

func (a *RecoveryAgent) RetransmitBatch(batch RetransmitBatch) {
	if len(batch) > 0 {
		a.Logger.Printf("Retransmitting %d batches of %d frames total\n", len(batch), batch.NFrames())
	}
	for _, b := range batch {
		if b.Level == EncryptionLevelInitial && (len(b.Frames) > 200 || b.Frames[0].FrameType() == StreamType) { // Simple heuristic to detect first Initial packet
			packet := NewInitialPacket(a.conn)
			packet.Frames = b.Frames
			a.conn.SendPacket.Submit(PacketToSend{Packet: packet, EncryptionLevel: EncryptionLevelInitial})
			return
		}
		for _, f := range b.Frames {
			a.conn.FrameQueue.Submit(QueuedFrame{f, b.Level})
		}
	}
}

type RetransmitBatch []RetransmittableFrames

type RetransmittableFrames struct {
	Frames    []Frame
	Timestamp time.Time
	Level     EncryptionLevel
}

func NewRetransmittableFrames(frames []Frame, level EncryptionLevel) *RetransmittableFrames {
	r := new(RetransmittableFrames)
	r.Frames = frames
	r.Timestamp = time.Now()
	r.Level = level
	return r
}
func (a RetransmitBatch) Less(i, j int) bool { return a[i].Timestamp.Before(a[j].Timestamp) }
func (a RetransmitBatch) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a RetransmitBatch) Len() int           { return len(a) }
func (a RetransmitBatch) NFrames() int {
	n := 0
	for _, rf := range a {
		n += len(rf.Frames)
	}
	return n
}
