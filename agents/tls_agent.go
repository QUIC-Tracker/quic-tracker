package agents

import (
	"encoding/hex"
	. "github.com/QUIC-Tracker/quic-tracker"
)

type TLSStatus struct {
	Completed bool
	Packet
	Error     error
}

// The TLSAgent is responsible of interacting with the TLS-1.3 stack. It waits on the CRYPTO streams for new data and
// feed it to the TLS stack. Any response is queued in a corresponding CRYPTO frame, unless disabled using
// DisableFrameSending. The TLSAgent will broadcast when new encryption or decryption levels are available.
type TLSAgent struct {
	BaseAgent
	TLSStatus  Broadcaster //type: TLSStatus
	ResumptionTicket Broadcaster //type: []byte
	DisableFrameSending bool
}

func (a *TLSAgent) Run(conn *Connection) {
	a.Init("TLSAgent", conn.OriginalDestinationCID)
	a.TLSStatus = NewBroadcaster(10)
	a.ResumptionTicket = NewBroadcaster(10)

	encryptionLevels := []*DirectionalEncryptionLevel{
		{EncryptionLevel: EncryptionLevelHandshake},
		{EncryptionLevel: EncryptionLevelHandshake, Read: true},
		{EncryptionLevel: EncryptionLevel1RTT},
		{EncryptionLevel: EncryptionLevel1RTT, Read: true},
	}

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	cryptoChans := map[PNSpace]chan interface{}{
		PNSpaceInitial:   make(chan interface{}, 1000),
		PNSpaceHandshake: make(chan interface{}, 1000),
		PNSpaceAppData:   make(chan interface{}, 1000),
	}
	for space, channel := range cryptoChans {
		conn.CryptoStreams.Get(space).ReadChan.Register(channel)
	}

	var resumptionTicketSent bool

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)

		for {
			select {
			case i := <-incomingPackets:
				packet := i.(Packet)
				if _, ok := packet.(Framer); !ok {
					break
				}
				cryptoChan := cryptoChans[packet.PNSpace()]

				var handshakeData []byte

			forLoop:
				for {
					select {
					case i := <-cryptoChan:
						handshakeData = append(handshakeData, i.([]byte)...)
					default:
						break forLoop
					}
				}

				a.Logger.Printf("Received %s packet in PN space %s and %d bytes from the corresponding crypto stream\n", packet.Header().PacketType().String(), packet.PNSpace().String(), len(handshakeData))

				switch packet.(type) {
				case Framer:
					if len(handshakeData) > 0 {
						tlsOutput, notCompleted, err := conn.Tls.HandleMessage(handshakeData, PNSpaceToEpoch[packet.PNSpace()])

						if err != nil {
							a.Logger.Printf("TLS error occured: %s\n", err.Error())
							a.TLSStatus.Submit(TLSStatus{false, packet, err})
						}

						conn.CryptoStateLock.Lock()
						if conn.CryptoStates[EncryptionLevelHandshake] == nil {
							conn.CryptoStates[EncryptionLevelHandshake] = new(CryptoState)
						}

						if conn.CryptoStates[EncryptionLevelHandshake] != nil {
							if conn.CryptoStates[EncryptionLevelHandshake].HeaderRead == nil && len(conn.Tls.HandshakeReadSecret()) > 0 {
								a.Logger.Printf("Installing handshake read crypto with secret %s\n", hex.EncodeToString(conn.Tls.HandshakeReadSecret()))
								conn.CryptoStates[EncryptionLevelHandshake].InitRead(conn.Tls, conn.Tls.HandshakeReadSecret())
							}
							if conn.CryptoStates[EncryptionLevelHandshake].HeaderWrite == nil && len(conn.Tls.HandshakeWriteSecret()) > 0 {
								a.Logger.Printf("Installing handshake write crypto with secret %s\n", hex.EncodeToString(conn.Tls.HandshakeWriteSecret()))
								conn.CryptoStates[EncryptionLevelHandshake].InitWrite(conn.Tls, conn.Tls.HandshakeWriteSecret())
							}
						}

						if len(tlsOutput) > 0 && !a.DisableFrameSending {
							for _, m := range tlsOutput {
								conn.FrameQueue.Submit(QueuedFrame{NewCryptoFrame(conn.CryptoStreams.Get(EpochToPNSpace[m.Epoch]), m.Data), EpochToEncryptionLevel[m.Epoch]})
							}
						}

						if !notCompleted && conn.CryptoStates[EncryptionLevel1RTT] == nil {
							a.Logger.Printf("Handshake has completed, installing protected crypto {read=%s, write=%s}\n", hex.EncodeToString(conn.Tls.ProtectedReadSecret()), hex.EncodeToString(conn.Tls.ProtectedWriteSecret()))
							conn.CryptoStates[EncryptionLevel1RTT] = NewProtectedCryptoState(conn.Tls, conn.Tls.ProtectedReadSecret(), conn.Tls.ProtectedWriteSecret())

							// TODO: Check negotiated ALPN ?

							err = conn.TLSTPHandler.ReceiveExtensionData(conn.Tls.ReceivedQUICTransportParameters())
							if err != nil {
								a.Logger.Printf("Failed to decode extension data: %s\n", err.Error())
								a.TLSStatus.Submit(TLSStatus{false, packet, err})
							} else {
								conn.TransportParameters.Submit(*conn.TLSTPHandler.ReceivedParameters)
								a.TLSStatus.Submit(TLSStatus{true, packet, err})
							}
						}

						for _, e := range encryptionLevels {
							if !e.Available && conn.CryptoStates[e.EncryptionLevel] != nil && ((e.Read && conn.CryptoStates[e.EncryptionLevel].HeaderRead != nil) || (!e.Read && conn.CryptoStates[e.EncryptionLevel].HeaderWrite != nil)) {
								e.Available = true
								conn.EncryptionLevels.Submit(*e)
							}
						}
						conn.CryptoStateLock.Unlock()

						if !resumptionTicketSent && len(conn.Tls.ResumptionTicket()) > 0 {
							a.ResumptionTicket.Submit(conn.Tls.ResumptionTicket())
						}
					}
				default:
					// The packet does not impact the TLS agent
				}
			case <-a.close:
				return
			}
		}
	}()
}
