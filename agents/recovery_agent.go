package agents

import (
	. "github.com/mpiraux/master-thesis"
	"time"
)

type RecoveryAgent struct {
	BaseAgent
	conn                 *Connection
	retransmissionBuffer map[PNSpace]map[uint64]RetransmittableFrames
	TimerValue           time.Duration
}

func (a *RecoveryAgent) Run(conn *Connection) {
	a.Init("RecoveryAgent", conn.SourceCID)
	a.conn = conn

	a.retransmissionBuffer = map[PNSpace]map[uint64]RetransmittableFrames{
		PNSpaceInitial:   make(map[uint64]RetransmittableFrames),
		PNSpaceHandshake: make(map[uint64]RetransmittableFrames),
		PNSpaceAppData:   make(map[uint64]RetransmittableFrames),
	}
	retransmissionTicker := time.NewTicker(100 * time.Millisecond)

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	outgoingPackets := make(chan interface{}, 1000)
	conn.OutgoingPackets.Register(outgoingPackets)

	eLAvailable := make(chan interface{}, 1000)
	conn.EncryptionLevelsAvailable.Register(eLAvailable)

	go func() {
		for {
			select {
			case <-retransmissionTicker.C:
				var batch RetransmitBatch
				for _, buffer := range a.retransmissionBuffer {
					for k, v := range buffer {
						if time.Now().Sub(v.Timestamp) > a.TimerValue {
							batch = append(batch, v)
							delete(buffer, k)
						}
					}
				}
				a.RetransmitBatch(batch)
			case i := <-incomingPackets:
				switch p := i.(type) {
				case Framer:
					for _, frame := range p.GetAll(AckType) {
						a.Logger.Printf("Processing ACK frame in packet %s\n", p.ShortString())
						a.RetransmitBatch(a.ProcessAck(frame.(*AckFrame), p.PNSpace()))
					}
					if !p.Contains(AckType) && p.PNSpace() == PNSpaceInitial { // Some implementations do not send ACK in this PNSpace
						a.Logger.Printf("Packet %s doesn't contain ACK frames, emptying the corresponding retransmission buffer anyway\n", p.ShortString())
						a.retransmissionBuffer[p.PNSpace()] = make(map[uint64]RetransmittableFrames)
					}
				}
			case i := <-outgoingPackets:
				switch p := i.(type) {
				case Framer:
					frames := p.GetRetransmittableFrames()
					if len(frames) > 0 {
						fullPacketNumber := (a.conn.PacketNumber[p.PNSpace()] & 0xffffffff00000000) | uint64(p.Header().PacketNumber())
						a.retransmissionBuffer[p.PNSpace()][fullPacketNumber] = *NewRetransmittableFrames(frames, p.EncryptionLevel())
					}
				}
			case i := <-eLAvailable:
				eL := i.(DirectionalEncryptionLevel)
				if eL.EncryptionLevel == EncryptionLevel1RTT { // Handshake has completed, empty the retransmission buffers
					a.Logger.Printf("Handshake has completed, emptying the two retransmission buffers")
					a.retransmissionBuffer[PNSpaceInitial] = make(map[uint64]RetransmittableFrames)
					a.retransmissionBuffer[PNSpaceHandshake] = make(map[uint64]RetransmittableFrames)
				}
			case <-a.close:
				return
			}
		}
	}()
}

func (a *RecoveryAgent) ProcessAck(ack *AckFrame, space PNSpace) RetransmitBatch { // Triggers fast retransmit and removes frames scheduled to be retransmitted
	threshold := uint64(1000)
	var frames RetransmitBatch
	currentPacketNumber := ack.LargestAcknowledged
	buffer := a.retransmissionBuffer[space]
	delete(buffer, currentPacketNumber)
	for i := uint64(0); i < ack.AckBlocks[0].Block && i < threshold; i++ {
		currentPacketNumber--
		delete(buffer, currentPacketNumber)
	}
	for _, ackBlock := range ack.AckBlocks[1:] {
		for i := uint64(0); i <= ackBlock.Gap && i < threshold; i++ { // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			if f, ok := buffer[currentPacketNumber]; ok {
				frames = append(frames, f)
			}
			currentPacketNumber--
			delete(buffer, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.Block && i < threshold; i++ {
			currentPacketNumber--
			delete(buffer, currentPacketNumber)
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
			a.conn.SendPacket(packet, EncryptionLevelInitial)
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
