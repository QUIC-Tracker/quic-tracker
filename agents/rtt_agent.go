package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"time"
	"math"
)

type RTTAgent struct {
	BaseAgent
	conn *Connection
	MinRTT             uint64
	LatestRTT          uint64
	SmoothedRTT        uint64
	RTTVar             uint64
	MaxAckDelay        uint64
	SentPackets        map[PNSpace]map[PacketNumber]SentPacket
	LargestSentPackets map[PNSpace]PacketNumber
}

type SentPacket struct {
	sent    time.Time
	ackOnly bool
	size    int
}

func (a *RTTAgent) Run(conn *Connection) {
	a.Init("RTTAgent", conn.OriginalDestinationCID)
	a.conn = conn
	a.MinRTT = math.MaxUint64

	a.SentPackets = map[PNSpace]map[PacketNumber]SentPacket{
		PNSpaceInitial:   make(map[PacketNumber]SentPacket),
		PNSpaceHandshake: make(map[PacketNumber]SentPacket),
		PNSpaceAppData:   make(map[PacketNumber]SentPacket),
	}

	a.LargestSentPackets = make(map[PNSpace]PacketNumber)

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)
	outgoingPackets := conn.OutgoingPackets.RegisterNewChan(1000)

	go func() { // TODO: Support ACK_ECN
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)

		for {
			select {
			case i := <-outgoingPackets:
				switch p := i.(type) {
				case Framer:
					packetNumber := p.Header().PacketNumber()
					if packetNumber > PacketNumber(a.LargestSentPackets[p.PNSpace()]) {
						a.LargestSentPackets[p.PNSpace()] = packetNumber
					}
					a.SentPackets[p.PNSpace()][packetNumber] = SentPacket{time.Now(), p.OnlyContains(AckType), len(p.Encode(p.EncodePayload()))}
				}
			case i := <-incomingPackets:
				switch p := i.(type) {
				case Framer:
					for _, f := range p.GetAll(AckType) {
						ack := f.(*AckFrame)

						if sp, ok := a.SentPackets[p.PNSpace()][ack.LargestAcknowledged]; ok {
							var ackDelayExponent uint64
							if conn.TLSTPHandler.ReceivedParameters != nil {
								ackDelayExponent = conn.TLSTPHandler.ReceivedParameters.AckDelayExponent
							}
							if ackDelayExponent == 0 {
								ackDelayExponent = 3
							}
							a.LatestRTT = uint64(p.ReceiveContext().Timestamp.Sub(sp.sent).Nanoseconds() / int64(time.Microsecond))
							a.UpdateRTT(ack.AckDelay * (2 << (ackDelayExponent - 1)), sp.ackOnly)
						}
					}

				}
			case <-a.close:
				return
			}
		}
	}()
}

func (a *RTTAgent) UpdateRTT(ackDelay uint64, ackOnly bool) { // TODO: https://tools.ietf.org/html/draft-ietf-quic-recovery-13#section-3.5.5
	if a.LatestRTT < a.MinRTT {
		a.MinRTT = a.LatestRTT
	}

	if a.LatestRTT - a.MinRTT > ackDelay {
		a.LatestRTT -= ackDelay
	}

	if !ackOnly && ackDelay > a.MaxAckDelay {
		a.MaxAckDelay = ackDelay
	}

	if a.SmoothedRTT == 0 {
		a.SmoothedRTT = a.LatestRTT
		a.RTTVar = a.LatestRTT / 2
	} else {
		var RTTVarSample uint64
		if a.SmoothedRTT < a.LatestRTT {
			RTTVarSample = -(a.SmoothedRTT - a.LatestRTT)
		} else {
			RTTVarSample = a.SmoothedRTT - a.LatestRTT
		}
		a.RTTVar = uint64(0.75 * float64(a.RTTVar) + 0.25 * float64(RTTVarSample))
		a.SmoothedRTT = uint64(0.875 * float64(a.SmoothedRTT) + 0.125 * float64(a.LatestRTT))
	}

	a.conn.MinRTT = a.MinRTT
	a.conn.SmoothedRTT = a.SmoothedRTT
	a.conn.RTTVar = a.RTTVar

	a.conn.QLogEvents <- a.conn.QLogTrace.NewEvent(qlog.Categories.Recovery.Category, qlog.Categories.Recovery.MetricsUpdated, qlog.MetricUpdate{
		LatestRTT: a.LatestRTT / 1000,
		MaxAckDelay: a.MaxAckDelay / 1000,
		SmoothedRTT: a.conn.SmoothedRTT / 1000,
		RTTVariance: a.conn.RTTVar / 1000,
		MinRTT: a.conn.MinRTT / 1000,
	})

	a.Logger.Printf("LatestRTT = %d, MinRTT = %d, SmoothedRTT = %d, RTTVar = %d", a.LatestRTT, a.MinRTT, a.SmoothedRTT, a.RTTVar)
}
