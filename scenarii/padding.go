package scenarii

import (
	m "masterthesis"
	"github.com/davecgh/go-spew/spew"
	"strings"
)

const (
	P_VNDidNotComplete = 1
)

type PaddingScenario struct {
	AbstractScenario
}

func NewPaddingScenario() *PaddingScenario {
	return &PaddingScenario{AbstractScenario{"padding", 1, false}}
}
func (s *PaddingScenario) Run(conn *m.Connection, trace *m.Trace) {
	sendEmptyInitialPacket := func() {
		var initialLength int
		if conn.UseIPv6 {
			initialLength = m.MinimumInitialLengthv6
		} else {
			initialLength = m.MinimumInitialLength
		}

		initialPacket := m.NewInitialPacket(make([]m.StreamFrame, 0, 1), make([]m.PaddingFrame, 0, initialLength), conn)

		paddingLength := initialLength - (m.LongHeaderSize + len(initialPacket.EncodePayload()) + conn.Cleartext.Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			initialPacket.Padding = append(initialPacket.Padding, *new(m.PaddingFrame))
		}

		conn.SendHandshakeProtectedPacket(initialPacket)
	}

	sendEmptyInitialPacket()
	packet, err, _ := conn.ReadNextPacket()

	if vn, ok := packet.(*m.VersionNegotationPacket); ok {
		if err := conn.ProcessVersionNegotation(vn); err != nil {
			trace.ErrorCode = P_VNDidNotComplete
			trace.Results["error"] = err.Error()
			return
		}
		sendEmptyInitialPacket()
	}

	packet, err, _ = conn.ReadNextPacket()

	if err != nil && !strings.Contains(err.Error(), "i/o timeout") {
		trace.Results["error"] = err.Error()
	} else if packet != nil {
		spew.Dump(packet)
	}
}
