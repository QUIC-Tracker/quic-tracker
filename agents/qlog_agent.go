package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"github.com/QUIC-Tracker/quic-tracker/qlog/qt2qlog"
)

type QLogAgent struct {
	BaseAgent
}

func (a *QLogAgent) Run(conn *Connection) {
	a.Init("QLogAgent", conn.OriginalDestinationCID)

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)
	outgoingPackets := conn.OutgoingPackets.RegisterNewChan(1000)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-incomingPackets:
				p := i.(Packet)
				jp := qt2qlog.ConvertPacket(p)
				jp.Header.PacketSize = int(p.ReceiveContext().PacketSize)
				e := conn.QLogTrace.NewEvent(qlog.Categories.Transport.Category, qlog.Categories.Transport.PacketReceived, jp)
				e.RelativeTime = uint64(p.ReceiveContext().Timestamp.Sub(conn.QLogTrace.ReferenceTime) / qlog.TimeUnits)
				conn.QLogEvents <- e
			case i := <-outgoingPackets:
				p := i.(Packet)
				jp := qt2qlog.ConvertPacket(p)
				jp.Header.PacketSize = int(i.(Packet).SendContext().PacketSize)
				e := conn.QLogTrace.NewEvent(qlog.Categories.Transport.Category, qlog.Categories.Transport.PacketSent, jp)
				e.RelativeTime = uint64(p.SendContext().Timestamp.Sub(conn.QLogTrace.ReferenceTime) / qlog.TimeUnits)
				conn.QLogEvents <- e
			case <-a.close:
				return
			}
		}
	}()

}
