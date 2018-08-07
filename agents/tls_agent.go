package agents

import (
	. "github.com/mpiraux/master-thesis"
	"encoding/hex"
	"github.com/dustin/go-broadcast"
)

type TLSStatus struct {
	Completed bool
	Packet
	Error error
}

type TLSAgent struct {
	BaseAgent
	TLSStatus broadcast.Broadcaster //type: TLSStatus
}

func (a *TLSAgent) Run(conn *Connection) {
	a.Init("TLSAgent", conn.SourceCID)
	a.TLSStatus = broadcast.NewBroadcaster(10)

	encryptionLevels := []DirectionalEncryptionLevel{{EncryptionLevelHandshake, false}, {EncryptionLevelHandshake, true}, {EncryptionLevel1RTT, false}, {EncryptionLevel1RTT, true}}
	encryptionLevelsAvailable := make(map[DirectionalEncryptionLevel]bool)

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	cryptoChans := map[PNSpace]chan interface{}{
		PNSpaceInitial:   make(chan interface{}, 1000),
		PNSpaceHandshake: make(chan interface{}, 1000),
		PNSpaceAppData:   make(chan interface{}, 1000),
	}
	for space, channel := range cryptoChans {
		conn.CryptoStreams.Get(space).ReadChan.Register(channel)
	}

	go func() {
		defer a.Logger.Println("Agent terminated")

	outerLoop:
		for {
			select {
			case i := <-incomingPackets:
				packet := i.(Packet)
				cryptoStream := conn.CryptoStreams.Get(packet.PNSpace())
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
						responseData, notCompleted, err := conn.Tls.HandleMessage(handshakeData, PNSpaceToEpoch[packet.PNSpace()])

						if err != nil {
							a.Logger.Printf("TLS error occured: %s\n", err.Error())
							a.TLSStatus.Submit(TLSStatus{false, packet, err})
						}

						if conn.CryptoStates[EncryptionLevelHandshake] == nil {
							conn.CryptoStates[EncryptionLevelHandshake] = new(CryptoState)
						}

						if conn.CryptoStates[EncryptionLevelHandshake] != nil {
							if conn.CryptoStates[EncryptionLevelHandshake].PacketRead == nil && len(conn.Tls.HandshakeReadSecret()) > 0 {
								a.Logger.Printf("Installing handshake read crypto with secret %s\n", hex.EncodeToString(conn.Tls.HandshakeReadSecret()))
								conn.CryptoStates[EncryptionLevelHandshake].InitRead(conn.Tls, conn.Tls.HandshakeReadSecret())
							}
							if conn.CryptoStates[EncryptionLevelHandshake].PacketWrite == nil && len(conn.Tls.HandshakeWriteSecret()) > 0 {
								a.Logger.Printf("Installing handshake write crypto with secret %s\n", hex.EncodeToString(conn.Tls.HandshakeWriteSecret()))
								conn.CryptoStates[EncryptionLevelHandshake].InitWrite(conn.Tls, conn.Tls.HandshakeWriteSecret())
							}
						}

						if len(responseData) > 0 {
							var responseEncryptionLevel EncryptionLevel
							if packet.EncryptionLevel() == EncryptionLevelInitial {
								responseEncryptionLevel = EncryptionLevelHandshake
							} else {
								responseEncryptionLevel = packet.EncryptionLevel()
							}
							conn.FrameQueue.Submit(QueuedFrame{NewCryptoFrame(cryptoStream, responseData), responseEncryptionLevel})
						}

						if !notCompleted { //TODO: Check that the resumption ticket does not trigger this if again
							a.Logger.Printf("Handshake has completed, installing protected crypto {read=%s, write=%s}\n", hex.EncodeToString(conn.Tls.ProtectedReadSecret()), hex.EncodeToString(conn.Tls.ProtectedWriteSecret()))
							conn.CryptoStates[EncryptionLevel1RTT] = NewProtectedCryptoState(conn.Tls, conn.Tls.ProtectedReadSecret(), conn.Tls.ProtectedWriteSecret())
							conn.ExporterSecret = conn.Tls.ExporterSecret()

							// TODO: Check negotiated ALPN ?

							err = conn.TLSTPHandler.ReceiveExtensionData(conn.Tls.ReceivedQUICTransportParameters())
							if err != nil {
								a.Logger.Printf("Failed to decode extension data: %s\n", err.Error())
								a.TLSStatus.Submit(TLSStatus{true, packet, err})
							}
							a.TLSStatus.Submit(TLSStatus{true, packet, nil})
						}

						for _, e := range encryptionLevels {
							if !encryptionLevelsAvailable[e] && conn.CryptoStates[e.EncryptionLevel] != nil && ((e.Read && conn.CryptoStates[e.EncryptionLevel].PacketRead != nil) || (!e.Read && conn.CryptoStates[e.EncryptionLevel].PacketWrite != nil)) {
								encryptionLevelsAvailable[e] = true
								conn.EncryptionLevelsAvailable.Submit(e)
							}
						}
					}
				default:
					// The packet does not impact the TLS agent
				}
			case <-a.close:
				break outerLoop
			}
		}
	}()
}
