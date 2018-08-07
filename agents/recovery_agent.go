package agents

import (
	. "github.com/mpiraux/master-thesis"
	"time"
)

type RecoveryAgent struct {
	BaseAgent
}

func (a *RecoveryAgent) Run (conn *Connection) {
	a.Init("RecoveryAgent", conn.SourceCID)
	
	go func() {
		for range conn.RetransmissionTicker.C {
			if conn.DisableRetransmits {
				continue
			}
			var frames RetransmitBatch
			for _, buffer := range conn.RetransmissionBuffer {
				for k, v := range buffer {
					if time.Now().Sub(v.Timestamp).Nanoseconds() > 500e6 {
						frames = append(frames, v)
						delete(buffer, k)
					}
				}
			}
			if len(frames) > 0 {
				conn.Logger.Printf("Retransmitting %d frames\n", len(frames))
			}
			conn.RetransmitFrames(frames)
		}
	}()
}