package scenarii

import (
	m "masterthesis"
	"time"
	"github.com/davecgh/go-spew/spew"
)

const (
	HR_DidNotRetransmitHandshake = 1
	HR_VNDidNotComplete          = 2
)

type HandshakeRetransmissionScenario struct {
	AbstractScenario
}
func NewHandshakeRetransmissionScenario() *HandshakeRetransmissionScenario {
	return &HandshakeRetransmissionScenario{AbstractScenario{"handshake_retransmission", 1, false}}
}
func (s *HandshakeRetransmissionScenario) Run(conn *m.Connection, trace *m.Trace) {
	conn.SendInitialPacket()

	arrivals := make([]uint64, 0, 10)

	var start time.Time
	for  i := 0; i < 20; i++ {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			break
		}

		if handshake, ok := packet.(*m.HandshakePacket); ok {
			var isRetransmit bool
			for _, frame := range handshake.StreamFrames {  // TODO Distinguish retransmits-only packets from packets bundling retransmitted and new frames ?
				if frame.StreamId == 0 && frame.Offset == 0 {
					isRetransmit = true
					break
				}
			}
			if !isRetransmit {
				continue
			}
			if start.IsZero() {
				start = time.Now()
			}
			arrivals = append(arrivals, uint64(time.Now().Sub(start).Seconds()*1000))
		} else if vn, ok := packet.(*m.VersionNegotationPacket); ok {
			if err := conn.ProcessVersionNegotation(vn); err != nil {
				trace.ErrorCode = HR_VNDidNotComplete
				trace.Results["error"] = err.Error()
				return
			}
			conn.SendInitialPacket()
		} else {
			spew.Dump(packet)
			return
		}
	}

	if len(arrivals) == 1 {
		trace.ErrorCode = HR_DidNotRetransmitHandshake
	}
	trace.Results["arrival_times"] = arrivals

}
