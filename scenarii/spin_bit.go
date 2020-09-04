package scenarii

import (
	. "github.com/tiferrei/quic-tracker"
)

const (
	SB_TLSHandshakeFailed = 1
	SB_DoesNotSpin        = 2
)

type SpinBitScenario struct {
	AbstractScenario
}

func NewSpinBitScenario() *SpinBitScenario {
	return &SpinBitScenario{AbstractScenario{name: "spin_bit", version: 1, ipv6: false}}
}
func (s *SpinBitScenario) Run(conn *Connection, trace *Trace, preferredPath string, debug bool) {
	connAgents := s.CompleteHandshake(conn, trace, SB_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	http := connAgents.AddHTTPAgent()
	responseChan := http.SendRequest(preferredPath, "GET", trace.Host, nil)

	var lastServerSpin SpinBit
	spins := 0

forLoop:
	for {
		select {
		case i := <-incomingPackets:
			switch p := i.(type) {
			case *ProtectedPacket:
				hdr := p.GetHeader().(*ShortHeader)
				if hdr.GetPacketNumber() >= conn.LastSpinNumber {
					if hdr.SpinBit != lastServerSpin {
						lastServerSpin = hdr.SpinBit
						spins++
					}
					conn.SpinBit = !hdr.SpinBit
					conn.LastSpinNumber = hdr.GetPacketNumber()
				}
				if conn.Streams.Get(0).ReadClosed && !conn.Streams.Get(4).WriteClosed {
					http.SendRequest(preferredPath, "GET", trace.Host, nil)
				}
			}
		case r := <-responseChan:
			if r != nil {
				http.SendRequest(preferredPath, "GET", trace.Host, nil)
			}
		case <-conn.ConnectionClosed:
			break forLoop
		case <-s.Timeout():
			break forLoop
		}
	}

	if spins <= 1 {
		trace.ErrorCode = SB_DoesNotSpin
	}
}
