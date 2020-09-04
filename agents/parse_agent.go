package agents

import (
	"bytes"
	cmp "github.com/google/go-cmp/cmp"
	. "github.com/tiferrei/quic-tracker"
	"unsafe"
)

// The ParsingAgent is responsible for decrypting and parsing the payloads received in UDP datagrams. It also decrypts
// the packet number if needed. Payloads that require a decryption level that is not available are put back into the
// UnprocessedPayloads queue.
type ParsingAgent struct {
	BaseAgent
	conn            *Connection
	DropRetransmits bool
}

func (a *ParsingAgent) Run(conn *Connection) {
	a.conn = conn
	a.Init("ParsingAgent", conn.OriginalDestinationCID)

	incomingPayloads := a.conn.IncomingPayloads.RegisterNewChan(1000)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
		packetSelect:
			select {
			case i := <-incomingPayloads:
				ic := i.(IncomingPayload)
				var off int
				for off < len(ic.Payload) {
					ciphertext := ic.Payload[off:]

					// Check most significant bit of first byte. If it's set, i.e byte & 0x80 == 0x80, it's a QUIC
					// long header, otherwise it's a short header.
					// The 4 following bytes indicate the QUIC Version. If these are 0x00000000, we're dealing
					// with a Version Negotiation packet.
					if ciphertext[0] & 0x80 == 0x80 && bytes.Equal(ciphertext[1:5], []byte{0, 0, 0, 0}) {
						ctx := ic.PacketContext
						ctx.PacketSize = uint16(len(ciphertext))
						packet := ReadVersionNegotationPacket(bytes.NewReader(ciphertext))
						a.Logger.Printf("Received Version Negotiation Packet with versions %v", packet.SupportedVersions)
						packet.SetReceiveContext(ctx)
						a.SaveCleartextPacket(ciphertext, packet.Pointer())
						a.conn.IncomingPackets.Submit(packet)
						break packetSelect
					}

					header := ReadHeader(bytes.NewReader(ciphertext), a.conn)
					cryptoState := a.conn.CryptoState(header.EncryptionLevel())

					switch header.GetPacketType() {
					case Initial, Handshake, ZeroRTTProtected, ShortHeaderPacket: // Decrypt PN
						if cryptoState != nil && cryptoState.HeaderRead != nil && cryptoState.Read != nil {
							a.Logger.Printf("Decrypting packet number of %s packet of length %d bytes", header.GetPacketType().String(), len(ciphertext))

							firstByteMask := byte(0x1F)
							if ciphertext[0] & 0x80 == 0x80 {
								firstByteMask = 0x0F
							}

							sample, pnOffset := GetPacketSample(header, ciphertext)
							mask := cryptoState.HeaderRead.Encrypt(sample, make([]byte, 5, 5))
							ciphertext[0] ^= mask[0] & firstByteMask

							pnLength := int(ciphertext[0] & 0x3) + 1

							for i := 0; i < pnLength; i++ {
								ciphertext[pnOffset+i] ^= mask[1+i]
							}
							header = ReadHeader(bytes.NewReader(ciphertext), a.conn) // Update PN
						} else {
							a.Logger.Printf("Crypto state for %s packet of length %d bytes is not ready, putting it back in waiting buffer\n", header.GetPacketType().String(), len(ciphertext))
							ic.Payload = ciphertext
							a.conn.UnprocessedPayloads.Submit(UnprocessedPayload{ic, header.EncryptionLevel()})
							break packetSelect
						}
					}

					a.Logger.Printf("Successfully decrypted header {type=%s, number=%d}\n", header.GetPacketType().String(), header.GetPacketNumber())

					hLen := header.HeaderLength()
					var packet Packet
					var cleartext []byte
					var consumed int
					switch header.GetPacketType() {
					case Handshake, Initial:
						lHeader := header.(*LongHeader)
						pLen := int(lHeader.Length.Value) - header.GetTruncatedPN().Length

						if hLen+pLen > len(ciphertext) {
							a.Logger.Printf("Payload length %d is past the %d received bytes, has PN decryption failed ? Aborting", hLen+pLen, len(ciphertext))
							break packetSelect
						}

						payload := cryptoState.Read.Decrypt(ciphertext[hLen:hLen+pLen], uint64(header.GetPacketNumber()), ciphertext[:hLen])
						if payload == nil {
							a.Logger.Printf("Could not decrypt packet {type=%s, number=%d}\n", header.GetPacketType().String(), header.GetPacketNumber())
							break packetSelect
						}

						cleartext = append(append(cleartext, ciphertext[:hLen]...), payload...)

						if lHeader.GetPacketType() == Initial {
							packet = ReadInitialPacket(bytes.NewReader(cleartext), a.conn)
						} else {
							packet = ReadHandshakePacket(bytes.NewReader(cleartext), a.conn)
						}

						consumed = hLen + pLen
					case ShortHeaderPacket: // Packets with a short header always include a 1-RTT protected payload.
						payload := cryptoState.Read.Decrypt(ciphertext[hLen:], uint64(header.GetPacketNumber()), ciphertext[:hLen])
						if payload == nil {
							a.Logger.Printf("Could not decrypt packet {type=%s, number=%d}\n", header.GetPacketType().String(), header.GetPacketNumber())
							statelessResetToken := ciphertext[len(ciphertext)-16:]
							if bytes.Equal(statelessResetToken, conn.TLSTPHandler.ReceivedParameters.StatelessResetToken) {
								a.Logger.Println("Received a Stateless Reset packet")
								cleartext = ciphertext
								packet = ReadStatelessResetPacket(bytes.NewReader(ciphertext))
							} else {
								break packetSelect
							}
						} else {
							cleartext = append(append(cleartext, ic.Payload[off:off+hLen]...), payload...)
							packet = ReadProtectedPacket(bytes.NewReader(cleartext), a.conn)
						}
						consumed = len(ic.Payload)
					case Retry:
						cleartext = ciphertext
						packet = ReadRetryPacket(bytes.NewReader(cleartext), a.conn)
						consumed = len(ic.Payload)
					default:
						a.Logger.Printf("Packet type is unknown, the first byte is %x\n", ciphertext[0])
						break packetSelect
					}

					a.Logger.Printf("Successfully parsed packet {type=%s, number=%d, length=%d}\n", header.GetPacketType().String(), header.GetPacketNumber(), len(cleartext))


					if framer, ok := packet.(Framer); ok {
						framer = a.filterOutRetransmits(framer)
						for _, frame := range framer.GetFrames() {
							a.conn.ReceiveFrameBuffer[framer.PNSpace()][frame.FrameType()] = append(a.conn.ReceiveFrameBuffer[framer.PNSpace()][frame.FrameType()], frame)
						}

						if framer.GetHeader().GetPacketNumber() > conn.LargestPNsReceived[framer.PNSpace()] {
							conn.LargestPNsReceived[framer.PNSpace()] = framer.GetHeader().GetPacketNumber()
						}
						packet = framer
					}

					off += consumed

					ctx := ic.PacketContext
					ctx.PacketSize = uint16(consumed)
					packet.SetReceiveContext(ctx)
					a.conn.IncomingPackets.Submit(packet)
					a.SaveCleartextPacket(cleartext, packet.Pointer())

				}
			case <-a.close:
				return
			}
		}
	}()
}

func (a *ParsingAgent) filterOutRetransmits(framer Framer) Framer {
	deleted := 0
	for initIndex := range framer.GetFrames() {
		index := initIndex - deleted
		frame := framer.GetFrames()[index]
		if frame.FrameType() == PingType {
			// TODO: My thought process was that for now we don't want to pass PINGs as they're time-dependent.
			framer.RemoveAtIndex(index)
			deleted++
			continue
		}

		for _, loggedFrame := range a.conn.ReceiveFrameBuffer[framer.PNSpace()][frame.FrameType()] {
			if cmp.Equal(frame, loggedFrame) {
				// Some implementations send *a lot* of PADDINGs. Don't flood the logs.
				if frame.FrameType() != PaddingFrameType {
					a.Logger.Printf("Detected retransmitted %v frame, removing.", frame.FrameType().String())
				}
				framer.RemoveAtIndex(index)
				deleted++
				break
			}
		}
	}
	return framer
}

func (a *ParsingAgent) SaveCleartextPacket(cleartext []byte, unique unsafe.Pointer) {
	if a.conn.ReceivedPacketHandler != nil {
		a.conn.ReceivedPacketHandler(cleartext, unique)
	}
}
