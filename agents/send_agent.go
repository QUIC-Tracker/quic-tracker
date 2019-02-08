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
	MTU           uint16
	FrameProducer []FrameProducer
}

func (a *SendingAgent) Run(conn *Connection) {
	a.Init("SendingAgent", conn.OriginalDestinationCID)

	preparePacket := conn.PreparePacket.RegisterNewChan(100)
	newEncryptionLevelAvailable := conn.EncryptionLevelsAvailable.RegisterNewChan(10)

	encryptionLevels := []EncryptionLevel{EncryptionLevelInitial, EncryptionLevel0RTT, EncryptionLevelHandshake, EncryptionLevel1RTT}
	encryptionLevelsAvailable := map[DirectionalEncryptionLevel]bool{
		{EncryptionLevelNone, false}:    true,
		{EncryptionLevelInitial, false}: true,
	}
	timers := make(map[EncryptionLevel]*time.Timer)
	timersArmed := make(map[EncryptionLevel]bool)
	for _, el := range encryptionLevels {
		timers[el] = time.NewTimer(0)
		timersArmed[el] = false
		if !timers[el].Stop() {
			<-timers[el].C
		}
	}

	fillAndSendPacket := func(packet Framer, level EncryptionLevel) {
		spaceLeft := int(a.MTU) - packet.Header().HeaderLength() - conn.CryptoStates[level].Write.Overhead()
		for i, fp := range a.FrameProducer {
			frames, more := fp.RequestFrames(spaceLeft, level, packet.Header().PacketNumber())
			if !more {
				a.FrameProducer[i] = nil
				a.FrameProducer = append(a.FrameProducer[:i], a.FrameProducer[i+1:]...)
			}
			for _, f := range frames {
				packet.AddFrame(f)
				spaceLeft -= int(f.FrameLength())
			}
		}

		if len(packet.GetFrames()) == 0 {
			a.Logger.Printf("Preparing a packet for encryption level %s resulted in an empty packet, discarding\n", level.String())
			conn.PacketNumber[packet.PNSpace()]-- // Avoids PN skipping
		} else {
			conn.SendPacket(packet, level)
		}
	}

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i :=<-preparePacket:
				eL := i.(EncryptionLevel)

				if eL == EncryptionLevelBest || eL == EncryptionLevelBestAppData {
					nEL := chooseBestEncryptionLevel(encryptionLevelsAvailable, eL == EncryptionLevelBestAppData)
					a.Logger.Printf("Chose %s as new encryption level for %s\n", nEL, eL)
					eL = nEL
				}
				if encryptionLevelsAvailable[DirectionalEncryptionLevel{eL, false}] || !timersArmed[eL] {
					timers[eL].Reset(2 * time.Millisecond)
					timersArmed[eL] = true
				}
			case <-timers[EncryptionLevelInitial].C:
				fillAndSendPacket(NewInitialPacket(conn), EncryptionLevelInitial)
				timersArmed[EncryptionLevelInitial] = false
			case <-timers[EncryptionLevel0RTT].C:
				fillAndSendPacket(NewZeroRTTProtectedPacket(conn), EncryptionLevel0RTT)
				timersArmed[EncryptionLevel0RTT] = false
			case <-timers[EncryptionLevelHandshake].C:
				fillAndSendPacket(NewHandshakePacket(conn), EncryptionLevelHandshake)
				timersArmed[EncryptionLevelHandshake] = false
			case <-timers[EncryptionLevel1RTT].C:
				fillAndSendPacket(NewProtectedPacket(conn), EncryptionLevel1RTT)
				timersArmed[EncryptionLevel1RTT] = false
			case i := <-newEncryptionLevelAvailable:
				dEL := i.(DirectionalEncryptionLevel)
				if dEL.Read {
					continue
				}
				eL := dEL.EncryptionLevel
				encryptionLevelsAvailable[dEL] = true
				timers[eL].Reset(0)
			case <-a.close:
				return
			}
		}
	}()
}

var elOrder = []DirectionalEncryptionLevel{{EncryptionLevel1RTT, false}, {EncryptionLevel0RTT, false}, {EncryptionLevelHandshake, false}, {EncryptionLevelInitial, false}}
var elAppDataOrder = []DirectionalEncryptionLevel{{EncryptionLevel1RTT, false}, {EncryptionLevel0RTT, false}}

func chooseBestEncryptionLevel(elAvailable map[DirectionalEncryptionLevel]bool, restrictAppData bool) EncryptionLevel {
	order := elOrder
	if restrictAppData {
		order = elAppDataOrder
	}
	for _, dEL := range order {
		if elAvailable[dEL] {
			return dEL.EncryptionLevel
		}
	}
	if restrictAppData {
		return EncryptionLevel1RTT
	}
	return order[len(order)-1].EncryptionLevel
}
