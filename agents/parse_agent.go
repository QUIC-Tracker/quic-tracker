package agents

import (
	. "github.com/mpiraux/master-thesis"
	"unsafe"
	"bytes"
)

type ParsingAgent struct {
	BaseAgent
	conn *Connection
}

func (a *ParsingAgent) Run(conn *Connection) {
	a.conn = conn
	a.Init("ParsingAgent", conn.SourceCID)

	incomingPayloads := make(chan interface{})
	a.conn.IncomingPayloads.Register(incomingPayloads)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
		packetSelect:
			select {
			case i := <-incomingPayloads:
				udpPayload := i.([]byte)
				var off int
				for off < len(udpPayload) {
					ciphertext := udpPayload[off:]
					header := ReadHeader(bytes.NewReader(ciphertext), a.conn)
					cryptoState := a.conn.CryptoStates[header.EncryptionLevel()]
					var pnLength int

					switch header.PacketType() {
					case Initial, Handshake, ZeroRTTProtected, ShortHeaderPacket: // Decrypt PN
						if cryptoState != nil && cryptoState.PacketRead != nil && cryptoState.Read != nil {
							a.Logger.Printf("Decrypting packet number of %s packet of length %d bytes", header.PacketType().String(), len(ciphertext))

							sample, sampleOffset := GetPacketSample(header, ciphertext)
							pn := cryptoState.PacketRead.Encrypt(sample, ciphertext[sampleOffset-4:sampleOffset])
							pnbuf := bytes.NewReader(pn)
							DecodePacketNumber(pnbuf)
							pnLength = len(pn) - pnbuf.Len()
							copy(ciphertext[sampleOffset-4:sampleOffset], pn[:pnLength])
							header = ReadHeader(bytes.NewReader(ciphertext), a.conn) // Update PN
						} else {
							a.Logger.Printf("Packet number of %s packet of length %d bytes could not be decrypted, putting it back in waiting buffer\n", header.PacketType().String(), len(ciphertext))
							a.conn.UnprocessedPayloads.Submit(UnprocessedPayload{header.EncryptionLevel(), ciphertext})
							break packetSelect
						}
					}

					a.Logger.Printf("Successfully decrypted header {type=%s, number=%d}\n", header.PacketType().String(), header.PacketNumber())

					if lHeader, ok := header.(*LongHeader); ok && lHeader.Version == 0x00000000 {
						packet := ReadVersionNegotationPacket(bytes.NewReader(ciphertext))

						a.SaveCleartextPacket(ciphertext, packet.Pointer())
						a.conn.IncomingPackets.Submit(packet)

						break packetSelect
					} else {
						hLen := header.Length()
						var packet Packet
						var cleartext []byte
						switch header.PacketType() {
						case Handshake, Initial:
							lHeader := header.(*LongHeader)
							pLen := int(lHeader.PayloadLength) - pnLength

							if hLen+pLen > len(ciphertext) {
								a.Logger.Printf("Payload length is past the received bytes, has PN decryption failed ? Aborting")
								break packetSelect
							}

							payload, err := cryptoState.Read.Open(nil, EncodeArgs(header.PacketNumber()), ciphertext[hLen:hLen+pLen], ciphertext[:hLen])
							if err != nil {
								a.Logger.Printf("Could not decrypt packet {type=%s, number=%d}: %s\n", header.PacketType().String(), header.PacketNumber(), err.Error())
								break packetSelect
							}

							cleartext = append(append(cleartext, ciphertext[:hLen]...), payload...)

							if lHeader.PacketType() == Initial {
								packet = ReadInitialPacket(bytes.NewReader(cleartext), a.conn)
							} else {
								packet = ReadHandshakePacket(bytes.NewReader(cleartext), a.conn)
							}

							off += hLen + pLen
						case ShortHeaderPacket: // Packets with a short header always include a 1-RTT protected payload.
							payload, err := cryptoState.Read.Open(nil, EncodeArgs(header.PacketNumber()), ciphertext[hLen:], ciphertext[:hLen])
							if err != nil {
								a.Logger.Printf("Could not decrypt packet {type=%s, number=%d}: %s\n", header.PacketType().String(), header.PacketNumber(), err.Error())
								break packetSelect
							}
							cleartext = append(append(cleartext, udpPayload[off:off+hLen]...), payload...)
							packet = ReadProtectedPacket(bytes.NewReader(cleartext), a.conn)
							off = len(udpPayload)
						case Retry:
							a.Logger.Println("TODO PR#1498")
							break packetSelect
						default:
							a.Logger.Printf("Packet type is unknown, the first byte is %x\n", ciphertext[0])
							break packetSelect
						}

						a.Logger.Printf("Successfully parsed packet {type=%s, number=%d, length=%d}\n", header.PacketType().String(), header.PacketNumber(), len(cleartext))

						a.conn.IncomingPackets.Submit(packet)
						a.SaveCleartextPacket(cleartext, packet.Pointer())
					}
				}
			case <-a.close:
				return
			}
		}
	}()
}

func (a *ParsingAgent) SaveCleartextPacket(cleartext []byte, unique unsafe.Pointer) {
	if a.conn.ReceivedPacketHandler != nil {
		a.conn.ReceivedPacketHandler(cleartext, unique)
	}
}
