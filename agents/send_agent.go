package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"time"
)

// The SendingAgent is responsible of bundling frames for sending from other agents into packets. If the frames queued
// for a given encryption level are smaller than a given MTU, it will wait a window of 5ms before sending them in the hope
// that more will be queued. Frames that require an unavailable encryption level are queued until it is made available.
// It also merge the ACK frames inside a given packet before sending.
type SendingAgent struct {
	BaseAgent
	MTU                         uint16
	FrameProducer               []FrameProducer
	DontCoalesceZeroRTT         bool
	KeepDroppedEncryptionLevels bool
}

func (a *SendingAgent) Run(conn *Connection) {
	a.Init("SendingAgent", conn.OriginalDestinationCID)

	preparePacket := conn.PreparePacket.RegisterNewChan(100)
	sendPacket := conn.SendPacket.RegisterNewChan(100)
	elChan := conn.EncryptionLevels.RegisterNewChan(10)

	encryptionLevels := map[DirectionalEncryptionLevel]bool{
		{EncryptionLevel: EncryptionLevelInitial, Available: true}:    true,
		{EncryptionLevel: EncryptionLevelNone, Available: true}:       true,
		{EncryptionLevel: EncryptionLevel0RTT, Available: false}:      true,
		{EncryptionLevel: EncryptionLevelHandshake, Available: false}: true,
		{EncryptionLevel: EncryptionLevel1RTT, Available: false}:      true,
	}
	bestEncryptionLevels := map[EncryptionLevel]EncryptionLevel{
		EncryptionLevelBest: EncryptionLevelInitial,
	}
	timers := make(map[EncryptionLevel]*time.Timer)
	timersArmed := make(map[EncryptionLevel]bool)
	for dEL := range encryptionLevels {
		el := dEL.EncryptionLevel
		if dEL.EncryptionLevel != EncryptionLevelNone {
			timers[el] = time.NewTimer(0)
			timersArmed[el] = false
			if !timers[el].Stop() {
				<-timers[el].C
			}
		}
	}

	initialSent := false

	fillPacket := func(packet Framer, level EncryptionLevel) Framer {
		spaceLeft := int(a.MTU) - packet.Header().HeaderLength() - conn.CryptoState(level).Write.Overhead()

	addFrame:
		for i, fp := range a.FrameProducer {
			levels := []EncryptionLevel{level}
			for eL, bEL := range bestEncryptionLevels {
				if bEL == level {
					levels = append(levels, eL)
				}
			}
			for _, l := range levels {
				if spaceLeft < 1 {
					break addFrame
				}
				frames, more := fp.RequestFrames(spaceLeft, l, packet.Header().PacketNumber())
				if !more {
					a.FrameProducer[i] = nil
					a.FrameProducer = append(a.FrameProducer[:i], a.FrameProducer[i+1:]...)
					break
				}
				for _, f := range frames {
					packet.AddFrame(f)
					spaceLeft -= int(f.FrameLength())
				}
			}
		}

		if len(packet.GetFrames()) == 0 {
			a.Logger.Printf("Preparing a packet for encryption level %s resulted in an empty packet, discarding\n", level.String())
			conn.PacketNumberLock.Lock()
			conn.PacketNumber[packet.PNSpace()]-- // Avoids PN skipping
			conn.PacketNumberLock.Unlock()
			return nil
		}
		return packet
	}

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-preparePacket:
				eL := i.(EncryptionLevel)

				if eL == EncryptionLevelBest || eL == EncryptionLevelBestAppData {
					nEL := chooseBestEncryptionLevel(encryptionLevels, eL == EncryptionLevelBestAppData)
					bestEncryptionLevels[eL] = nEL
					a.Logger.Printf("Chose %s as new encryption level for %s\n", nEL, eL)
					eL = nEL
				}
				if encryptionLevels[DirectionalEncryptionLevel{EncryptionLevel: eL, Read: false, Available: true}] && !timersArmed[eL] {
					timers[eL].Reset(2 * time.Millisecond)
					timersArmed[eL] = true
				}
			case <-timers[EncryptionLevelInitial].C:
				p := fillPacket(NewInitialPacket(conn), EncryptionLevelInitial)
				if p != nil {
					var initialLength int
					if conn.UseIPv6 {
						initialLength = MinimumInitialLengthv6
					} else {
						initialLength = MinimumInitialLength
					}
					initialLength -= conn.CryptoState(EncryptionLevelInitial).Write.Overhead()
					p.PadTo(initialLength)
					initialSent = true
					conn.DoSendPacket(p, EncryptionLevelInitial)
				}
				timersArmed[EncryptionLevelInitial] = false
			case <-timers[EncryptionLevel0RTT].C:
				if initialSent {
					p := fillPacket(NewZeroRTTProtectedPacket(conn), EncryptionLevel0RTT)
					if p != nil {
						conn.DoSendPacket(p, EncryptionLevel0RTT)
					}
				}
				timersArmed[EncryptionLevel0RTT] = false
			case <-timers[EncryptionLevelHandshake].C:
				p := fillPacket(NewHandshakePacket(conn), EncryptionLevelHandshake)
				if p != nil {
					conn.DoSendPacket(p, EncryptionLevelHandshake)
				}
				timersArmed[EncryptionLevelHandshake] = false
			case <-timers[EncryptionLevel1RTT].C:
				p := fillPacket(NewProtectedPacket(conn), EncryptionLevel1RTT)
				if p != nil {
					conn.DoSendPacket(p, EncryptionLevel1RTT)
				}
				timersArmed[EncryptionLevel1RTT] = false
			case i := <-elChan:
				dEL := i.(DirectionalEncryptionLevel)
				if dEL.Read {
					continue
				}
				eL := dEL.EncryptionLevel
				t := timers[eL]
				if !dEL.Available && !a.KeepDroppedEncryptionLevels {
					a.Logger.Println("Dropping encryption level", eL.String())
					encryptionLevels[dEL] = true
					t.Stop()
				} else if dEL.Available {
					encryptionLevels[dEL] = true
					dEL.Available = false
					delete(encryptionLevels, dEL)
					bestEncryptionLevels[EncryptionLevelBest] = chooseBestEncryptionLevel(encryptionLevels, false)
					bestEncryptionLevels[EncryptionLevelBestAppData] = chooseBestEncryptionLevel(encryptionLevels, true)
					t.Reset(2 * time.Millisecond)
				}
			case i := <-sendPacket:
				p := i.(PacketToSend)
				if p.EncryptionLevel == EncryptionLevelInitial && p.Packet.Header().PacketType() == Initial {
					initial := p.Packet.(*InitialPacket)
					if !a.DontCoalesceZeroRTT && bestEncryptionLevels[EncryptionLevelBestAppData] == EncryptionLevel0RTT {
						// Try to prepare a 0-RTT packet and squeeze it after the Initial
						zp := NewZeroRTTProtectedPacket(conn)
						fillPacket(zp, EncryptionLevel0RTT)
						if len(zp.GetFrames()) > 0 {
							zpBytes := conn.EncodeAndEncrypt(zp, EncryptionLevel0RTT)
							initialFrames := initial.GetFrames()
							initialLength := len(conn.EncodeAndEncrypt(initial, EncryptionLevelInitial))
							initial.Frames = nil
							for _, f := range initialFrames {
								if f.FrameType() != PaddingFrameType {
									initial.Frames = append(initial.Frames, f)
								}
							}
							initial.PadTo(initialLength - len(zpBytes))
							coalescedPackets := append(conn.EncodeAndEncrypt(initial, EncryptionLevelInitial), zpBytes...)
							conn.UdpConnection.Write(coalescedPackets)
							conn.PacketWasSent(initial)
							conn.PacketWasSent(zp)
							continue
						}
					}
					var initialLength int
					if conn.UseIPv6 {
						initialLength = MinimumInitialLengthv6
					} else {
						initialLength = MinimumInitialLength
					}
					initialLength -= conn.CryptoState(EncryptionLevelInitial).Write.Overhead()
					initial.PadTo(initialLength)
					initialSent = true
				}
				conn.DoSendPacket(p.Packet, p.EncryptionLevel)
			case <-a.close:
				return
			}
		}
	}()
}

var elOrder = []EncryptionLevel{EncryptionLevel1RTT, EncryptionLevelHandshake, EncryptionLevelInitial}
var elAppDataOrder = []EncryptionLevel{EncryptionLevel1RTT, EncryptionLevel0RTT}

func chooseBestEncryptionLevel(eLs map[DirectionalEncryptionLevel]bool, restrictAppData bool) EncryptionLevel {
	order := elOrder
	if restrictAppData {
		order = elAppDataOrder
	}
	for _, eL := range order {
		if eLs[DirectionalEncryptionLevel{EncryptionLevel: eL, Available: true}] {
			return eL
		}
	}
	if restrictAppData {
		return EncryptionLevel1RTT
	}
	return order[len(order)-1]
}
