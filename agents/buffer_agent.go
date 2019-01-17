package agents

import . "github.com/QUIC-Tracker/quic-tracker"

// The BufferAgent is in charge of waiting for a given decryption level to become available before putting
// ciphertexts that require this level back into the decryption queue.
type BufferAgent struct {
	BaseAgent
}

func (a *BufferAgent) Run(conn *Connection) {
	a.Init("BufferAgent", conn.OriginalDestinationCID)

	uPChan := make(chan interface{}, 1000)
	conn.UnprocessedPayloads.Register(uPChan)
	eLChan := make(chan interface{}, 1000)
	conn.EncryptionLevelsAvailable.Register(eLChan)

	unprocessedPayloads := make(map[EncryptionLevel][][]byte)
	encryptionLevelsAvailable := make(map[EncryptionLevel]bool)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-uPChan:
				u := i.(UnprocessedPayload)
				if !encryptionLevelsAvailable[u.EncryptionLevel] {
					unprocessedPayloads[u.EncryptionLevel] = append(unprocessedPayloads[u.EncryptionLevel], u.Payload)
				} else {
					conn.IncomingPayloads.Submit(u.Payload)
				}
			case i := <-eLChan:
				dEL := i.(DirectionalEncryptionLevel)
				if dEL.Read {
					eL := dEL.EncryptionLevel
					encryptionLevelsAvailable[eL] = true
					if len(unprocessedPayloads[eL]) > 0 {
						a.Logger.Printf("Encryption level %s is available, putting back %d unprocessed payloads into the buffer", eL.String(), len(unprocessedPayloads[eL]))
					}
					for _, uP := range unprocessedPayloads[eL] {
						conn.IncomingPayloads.Submit(uP)
					}
				}
			case <-a.close:
				return
			}
		}
	}()
}
