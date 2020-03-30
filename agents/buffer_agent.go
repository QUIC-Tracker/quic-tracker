package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	qt2qlog "github.com/QUIC-Tracker/quic-tracker/qlog/qt2qlog"
)

// The BufferAgent is in charge of waiting for a given decryption level to become available before putting
// ciphertexts that require this level back into the decryption queue.
type BufferAgent struct {
	BaseAgent
}

func (a *BufferAgent) Run(conn *Connection) {
	a.Init("BufferAgent", conn.OriginalDestinationCID)

	uPChan := conn.UnprocessedPayloads.RegisterNewChan(1000)
	eLChan := conn.EncryptionLevels.RegisterNewChan(1000)

	unprocessedPayloads := make(map[EncryptionLevel][]IncomingPayload)
	encryptionLevelsAvailable := make(map[EncryptionLevel]bool)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-uPChan:
				u := i.(UnprocessedPayload)
				if !encryptionLevelsAvailable[u.EncryptionLevel] {
					u.EncryptionLevel.String()
					conn.QLogEvents <- conn.QLogTrace.NewEvent(qlog.Categories.Transport.Category, qlog.Categories.Transport.PacketBuffered, qt2qlog.ConvertPacketBuffered(EncryptionLevelToPacketType[u.EncryptionLevel], "keys_unavailable"))
					unprocessedPayloads[u.EncryptionLevel] = append(unprocessedPayloads[u.EncryptionLevel], u.IncomingPayload)
				} else {
					conn.IncomingPayloads.Submit(u.IncomingPayload)
				}
			case i := <-eLChan:
				dEL := i.(DirectionalEncryptionLevel)
				if dEL.Available && dEL.Read {
					eL := dEL.EncryptionLevel
					encryptionLevelsAvailable[eL] = true
					if len(unprocessedPayloads[eL]) > 0 {
						a.Logger.Printf("Encryption level %s is available, putting back %d unprocessed payloads into the buffer", eL.String(), len(unprocessedPayloads[eL]))
					}
					for _, uP := range unprocessedPayloads[eL] {
						uP.WasBuffered = true
						conn.IncomingPayloads.Submit(uP)
					}
					unprocessedPayloads[eL] = nil
				}
			case <-a.close:
				return
			}
		}
	}()
}
