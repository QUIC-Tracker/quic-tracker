/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package masterthesis

import (
	"crypto/rand"
	"net"
	"bytes"
	"github.com/davecgh/go-spew/spew"
	"time"
	"os"
	"fmt"
	"errors"
	"sort"
	"github.com/mpiraux/pigotls"
	"crypto/cipher"
	"unsafe"
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	UseIPv6        bool
	Host           *net.UDPAddr

	Tls           *pigotls.Connection
	TLSTPHandler  *TLSTransportParameterHandler

	InitialCrypto   *CryptoState
	HandshakeCrypto *CryptoState
	ProtectedCrypto *CryptoState
	ZeroRTTCrypto   *CryptoState

	ClientRandom   []byte
	ExporterSecret []byte

	ReceivedPacketHandler func([]byte, unsafe.Pointer)
	SentPacketHandler     func([]byte, unsafe.Pointer)

	CryptoStream 		 Stream  // TODO: It should be a parent class without closing states
	Streams              Streams
	IncomingPackets		 chan Packet

	OriginalDestinationCID ConnectionID
	SourceCID              ConnectionID
	DestinationCID         ConnectionID
	Version                uint32

	PacketNumber         map[PNSpace]uint64
	ExpectedPacketNumber map[PNSpace]uint64

	ackQueue             map[PNSpace][]uint64 // Stores the packet numbers to be acked
	retransmissionBuffer map[PNSpace]map[uint64]RetransmittableFrames
	RetransmissionTicker *time.Ticker

	IgnorePathChallenge   bool
	DisableRetransmits    bool
	DisableIncPacketChan  bool
}
func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber(space PNSpace) uint64 {
	pn := c.PacketNumber[space]
	c.PacketNumber[space]++
	return pn
}
func (c *Connection) RetransmitFrames(frames RetransmitBatch) {  // TODO: Split in smaller packets if needed
	sort.Sort(frames)
	for _, f := range frames {
		switch f.PNSpace {
		case PNSpaceInitial:
			packet := NewInitialPacket(c)
			packet.Frames = f.Frames
			c.SendInitialProtectedPacket(packet)
		case PNSpaceHandshake:
			packet := NewHandshakePacket(c)
			packet.Frames = f.Frames
			c.SendHandshakeProtectedPacket(packet)
		case PNSpaceAppData:
			packet := NewProtectedPacket(c)
			packet.Frames = f.Frames
			c.SendProtectedPacket(packet)
		default:
		}
	}
}
func (c *Connection) SendFrames(frames []Frame) {
	if c.ProtectedCrypto != nil {
		packet := NewProtectedPacket(c)
		packet.Frames = frames
		c.SendProtectedPacket(packet)
	} else {
		packet := NewHandshakePacket(c)
		packet.Frames = frames
		c.SendHandshakeProtectedPacket(packet)
	}
}
func (c *Connection) SendPacket(packet Packet, cipher cipher.AEAD, pnCipher pigotls.Cipher) {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		if framePacket, ok := packet.(Framer); ok && len(framePacket.GetRetransmittableFrames()) > 0 {
			fullPacketNumber := (c.PacketNumber[packet.PNSpace()] & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())
			c.retransmissionBuffer[packet.PNSpace()][fullPacketNumber] = *NewRetransmittableFrames(framePacket.GetRetransmittableFrames(), packet.PNSpace())
		}

		payload := packet.EncodePayload()
		if lHeader, ok := packet.Header().(*LongHeader); ok {
			lHeader.PayloadLength = uint64(PacketNumberLen(lHeader.packetNumber) + len(payload) + cipher.Overhead())
		}

		if c.SentPacketHandler != nil {
			c.SentPacketHandler(packet.Encode(packet.EncodePayload()), packet.Pointer())
		}

		header := packet.EncodeHeader()
		protectedPayload := cipher.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), payload, header)
		packetBytes := append(header, protectedPayload...)

		var sampleOffset int
		sampleLength := 16
		switch h := packet.Header().(type) {
		case *LongHeader:
			sampleOffset = 6 + len(h.DestinationCID) + len(h.SourceCID) + int(VarIntLen(h.PayloadLength)) + 4
		case *ShortHeader:

			sampleOffset := 1 + len(h.DestinationCID) + 4

			if sampleOffset + sampleLength > len(packetBytes) {
				sampleOffset = len(packetBytes) - sampleLength
			}
		}
		sample := packetBytes[sampleOffset:sampleOffset+sampleLength]

		packetBytes[sampleOffset-4:sampleOffset] = pnCipher.Encrypt(sample, packetBytes[sampleOffset-4:sampleOffset])

		c.UdpConnection.Write(packetBytes)
	default:
		// Clients do not send cleartext packets
	}
}
func (c *Connection) SendInitialProtectedPacket(packet Packet) {
	c.SendPacket(packet, c.InitialCrypto.Write, c.InitialCrypto.PacketWrite)
}
func (c *Connection) SendHandshakeProtectedPacket(packet Packet) {
	c.SendPacket(packet, c.HandshakeCrypto.Write, c.HandshakeCrypto.PacketWrite)
}
func (c *Connection) SendProtectedPacket(packet Packet) {
	c.SendPacket(packet, c.ProtectedCrypto.Write, c.ProtectedCrypto.PacketWrite)
}
func (c *Connection) SendZeroRTTProtectedPacket(packet Packet) {
	c.SendPacket(packet, c.ZeroRTTCrypto.Write, c.ZeroRTTCrypto.PacketWrite)
}
func (c *Connection) GetInitialPacket() *InitialPacket {
	extensionData, err := c.TLSTPHandler.GetExtensionData()
	if err != nil {
		println(err)
		return nil
	}
	c.Tls.SetQUICTransportParameters(extensionData)

	clientHello, notComplete, err := c.Tls.HandleMessage(nil, pigotls.EpochInitial)
	if err != nil || !notComplete {
		println(err.Error())
		return nil
	}
	c.ClientRandom = make([]byte, 32, 32)
	copy(c.ClientRandom, clientHello[11:11+32])
	cryptoFrame := NewCryptoFrame(c.CryptoStream, clientHello)

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, cryptoFrame)
	paddingLength := initialLength - (initialPacket.header.Length() + len(initialPacket.EncodePayload()) + c.InitialCrypto.Write.Overhead())
	for i := 0; i < paddingLength; i++ {
		initialPacket.Frames = append(initialPacket.Frames, new(PaddingFrame))
	}

	return initialPacket
}

func (c *Connection) ProcessServerHello(packet Packet) (bool, Framer, error) { // Returns whether or not the TLS Handshake should continue
	if f, ok := packet.(Framer); ok && (f.Contains(ConnectionCloseType) || f.Contains(ApplicationCloseType)) {
		return false, nil, errors.New("connection closed")
	}

	lHeader := packet.Header().(*LongHeader)
	c.DestinationCID = lHeader.SourceCID  // TODO: see https://tools.ietf.org/html/draft-ietf-quic-transport-11#section-4.7

	var handshakeData []byte
	select {
		case handshakeData = <- c.CryptoStream.ReadChan:
		default:
	}

	var responsePacket Framer
	defer func() {
		if c.ackQueue[packet.PNSpace()] != nil && lHeader.PacketType() != Retry && packet.ShouldBeAcknowledged() {
			responsePacket.AddFrame(c.GetAckFrame(packet.PNSpace()))
	}}()

	switch packet.(type) {
	case Framer:
		if packet.(*InitialPacket) != nil {
			responsePacket = NewInitialPacket(c)
		} else if packet.(*HandshakePacket) != nil {
			responsePacket = NewHandshakePacket(c)
		} else if packet.(*ProtectedPacket) != nil {
			responsePacket = NewProtectedPacket(c)
		} else {
			return true, responsePacket, nil
		}

		if len(handshakeData) > 0 {
			responseData, notCompleted, err := c.Tls.HandleMessage(handshakeData, PNSpaceToEpoch[packet.PNSpace()])

			if err != nil {
				return notCompleted, responsePacket, err
			}

			if responseData != nil && len(responseData) > 0 {
				responsePacket.AddFrame(NewCryptoFrame(c.CryptoStream, responseData))
			}

			if c.HandshakeCrypto == nil && c.Tls.HandshakeReadSecret() != nil && c.Tls.HandshakeWriteSecret() != nil {
				c.HandshakeCrypto = NewProtectedCryptoState(c.Tls, c.Tls.HandshakeReadSecret(), c.Tls.HandshakeWriteSecret())
			}

			if !notCompleted {
				c.ProtectedCrypto = NewProtectedCryptoState(c.Tls, c.Tls.ProtectedReadSecret(), c.Tls.ProtectedWriteSecret())
				c.ExporterSecret = c.Tls.ExporterSecret()

				// TODO: Check negotiated ALPN ?

				err = c.TLSTPHandler.ReceiveExtensionData(c.Tls.ReceivedQUICTransportParameters())
				if err != nil {
					return false, responsePacket, err
				}
			}
			return notCompleted, responsePacket, nil
		}
	case *RetryPacket: // TODO: Reset the connection and handle the retry
		responsePacket = NewInitialPacket(c)

		var initialLength int
		if c.UseIPv6 {
			initialLength = MinimumInitialLengthv6
		} else {
			initialLength = MinimumInitialLength
		}
		paddingLength := initialLength - (responsePacket.Header().Length() + len(responsePacket.EncodePayload()) + c.InitialCrypto.Write.Overhead())
		for i := 0; i < paddingLength; i++ {
			responsePacket.AddFrame(new(PaddingFrame))
		}
	}

	return true, responsePacket, nil
}
func (c *Connection) ProcessVersionNegotation(vn *VersionNegotationPacket) error {
	var version uint32
	for _, v := range vn.SupportedVersions {
		if v >= MinimumVersion && v <= MaximumVersion {
			version = uint32(v)
		}
	}
	if version == 0 {
		return errors.New("no appropriate version found")
	}
	QuicVersion, QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
	c.TransitionTo(QuicVersion, QuicALPNToken, nil)
	return nil
}
func (c *Connection) ReadNextPackets() ([]Packet, error, []byte) {
	saveCleartext := func (ct []byte, p unsafe.Pointer) {if c.ReceivedPacketHandler != nil {c.ReceivedPacketHandler(ct, p)}}

	rec := make([]byte, MaxUDPPayloadSize, MaxUDPPayloadSize)
	i, _, err := c.UdpConnection.ReadFromUDP(rec)
	if err != nil {
		return nil, err, nil
	}
	rec = rec[:i]

	var packets []Packet
	var off int

	for len(rec) > off {
		header := ReadHeader(bytes.NewReader(rec[off:]), c)

		var packet Packet

		if lHeader, ok := header.(*LongHeader); ok && lHeader.Version == 0x00000000 {
			packet = ReadVersionNegotationPacket(bytes.NewReader(rec))
			for k := range c.retransmissionBuffer {
				delete(c.retransmissionBuffer, k)
			}
			saveCleartext(rec, packet.Pointer())
			off = len(rec)

			packets = append(packets, packet)
		} else {
			hLen := header.Length()
			var data []byte
			switch header.PacketType() {
			case Handshake, Initial, Retry:
				longHeader := header.(*LongHeader)
				pLen := int(longHeader.PayloadLength)

				payload, err := c.InitialCrypto.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[off+hLen:off+hLen+pLen], rec[off:off+hLen])
				if err != nil {
					return packets, err, rec
				}
				data = append(append(data, rec[off:off+hLen]...), payload...)
				off += hLen + pLen
			case ShortHeaderPacket:  // Packets with a short header always include a 1-RTT protected payload.
				if c.ProtectedCrypto == nil {
					println("Crypto state is not ready to decrypt protected packets")
					return c.ReadNextPackets() // Packet may have been reordered, TODO: Implement a proper packet queue instead of triggering retransmissions
				}
				payload, err := c.ProtectedCrypto.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[off+hLen:], rec[off:off+hLen])
				if err != nil {
					return packets, err, rec
				}
				data = append(append(data, rec[off:off+hLen]...), payload...)
				off = len(rec)
			case Retry:
				longHeader := header.(*LongHeader)
				pLen := int(longHeader.PayloadLength)
				data =
			default:
				spew.Dump(header)
				return packets, errors.New("unknown packet type"), rec
			}

			buffer := bytes.NewReader(data)

			switch header.PacketType() {
			case Handshake:
				packet = ReadHandshakePacket(buffer, c)
			case ShortHeaderPacket:
				packet = ReadProtectedPacket(buffer, c)
			case Initial:
				packet = ReadInitialPacket(buffer, c)
			case Retry:
				packet = ReadRetryPacket(buffer)
			}

			saveCleartext(data, packet.Pointer())

			if packet.PNSpace() != PNSpaceNoSpace {
				fullPacketNumber := (c.ExpectedPacketNumber[packet.PNSpace()] & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())

				for _, number := range c.ackQueue[packet.PNSpace()] {
					if number == fullPacketNumber {
						fmt.Fprintf(os.Stderr, "Received duplicate packet number %d\n", fullPacketNumber)
						spew.Dump(packet)
						return c.ReadNextPackets()
						// TODO: Should it be acked again ?
					}
				}
				c.ackQueue[packet.PNSpace()] = append(c.ackQueue[packet.PNSpace()], fullPacketNumber)
				c.ExpectedPacketNumber[packet.PNSpace()] = fullPacketNumber + 1

				if framePacket, ok := packet.(Framer); ok {
					for _, f := range framePacket.GetFrames() {
						if ack, ok := f.(*AckFrame); ok {
							c.RetransmitFrames(c.ProcessAck(ack, packet.PNSpace()))
						}
					}

					if pathChallenge := framePacket.GetFirst(PathChallengeType); !c.IgnorePathChallenge && pathChallenge != nil {
						c.SendFrames([]Frame{PathResponse{pathChallenge.(*PathChallenge).Data}})
					}
				}
			}

			packets = append(packets, packet)
		}
	}

	return packets, nil, rec
}
func (c *Connection) GetAckFrame(space PNSpace) *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.ackQueue[space]))
	packetNumbers := c.ackQueue[space]
	frame := new(AckFrame)
	frame.AckBlocks = make([]AckBlock, 0, 255)
	frame.LargestAcknowledged = packetNumbers[0]

	previous := frame.LargestAcknowledged
	ackBlock := AckBlock{}
	for _, number := range packetNumbers[1:] {
		if previous - number == 1 {
			ackBlock.block++
		} else {
			frame.AckBlocks = append(frame.AckBlocks, ackBlock)
			ackBlock = AckBlock{previous - number - 1, 0}
		}
		previous = number
	}
	frame.AckBlocks = append(frame.AckBlocks, ackBlock)
	if len(frame.AckBlocks) > 0 {
		frame.AckBlockCount = uint64(len(frame.AckBlocks) - 1)
	}
	return frame
}
func (c *Connection) ProcessAck(ack *AckFrame, space PNSpace) RetransmitBatch {
	threshold := uint64(1000)
	var frames RetransmitBatch
	currentPacketNumber := ack.LargestAcknowledged
	buffer := c.retransmissionBuffer[space]
	delete(buffer, currentPacketNumber)
	for i := uint64(0); i < ack.AckBlocks[0].block && i < threshold; i++ {
		currentPacketNumber--
		delete(buffer, currentPacketNumber)
	}
	for _, ackBlock := range ack.AckBlocks[1:] {
		for i := uint64(0); i <= ackBlock.gap && i < threshold; i++ {  // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			if f, ok := buffer[currentPacketNumber]; ok {
				frames = append(frames, f)
			}
			currentPacketNumber--
			delete(buffer, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.block && i < threshold; i++ {
			currentPacketNumber--
			delete(buffer, currentPacketNumber)
		}
	}
	return frames
}
func (c *Connection) TransitionTo(version uint32, ALPN string, resumptionSecret []byte) {
	var prevVersion uint32
	if c.Version == 0 {
		prevVersion = QuicVersion
	} else {
		prevVersion = c.Version
	}
	c.TLSTPHandler = NewTLSTransportParameterHandler(version, prevVersion)
	c.Version = version
	c.Tls = pigotls.NewConnection(c.ServerName, ALPN, resumptionSecret)
	c.InitialCrypto = NewInitialPacketProtection(c)
	c.Streams = make(map[uint64]*Stream)
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint16, reasonPhrase string) {
	pkt := NewProtectedPacket(c)
	if quicLayer {
		pkt.Frames = append(pkt.Frames, ConnectionCloseFrame{errCode,0, uint64(len(reasonPhrase)), reasonPhrase})
	} else {
		pkt.Frames = append(pkt.Frames, ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase})
	}
	c.SendProtectedPacket(pkt)
}
func (c *Connection) CloseStream(streamId uint64) {
	frame := *NewStreamFrame(streamId, c.Streams.Get(streamId), nil, true)
	if c.ProtectedCrypto == nil {
		pkt := NewHandshakePacket(c)
		pkt.Frames = append(pkt.Frames, frame)
		c.SendHandshakeProtectedPacket(pkt)
	} else {
		pkt := NewProtectedPacket(c)
		pkt.Frames = append(pkt.Frames, frame)
		c.SendProtectedPacket(pkt)
	}
}
func (c *Connection) SendHTTPGETRequest(path string, streamID uint64) {
	streamFrame := NewStreamFrame(streamID, c.Streams.Get(streamID), []byte(fmt.Sprintf("GET %s\r\n", path)), true)

	pp := NewProtectedPacket(c)
	pp.Frames = append(pp.Frames, streamFrame)
	c.SendProtectedPacket(pp)
}
func (c *Connection) Close() {
	c.RetransmissionTicker.Stop()
	c.Tls.Close()
	c.UdpConnection.Close()
}
func EstablishUDPConnection(addr *net.UDPAddr) (*net.UDPConn, error) {
	udpConn, err := net.DialUDP(addr.Network(), nil, addr)
	if err != nil {
		return nil, err
	}
	udpConn.SetDeadline(time.Now().Add(10 * time.Second))
	return udpConn, nil
}
func NewDefaultConnection(address string, serverName string, resumptionSecret []byte, useIPv6 bool) (*Connection, error) {
	scid := make([]byte, 8, 8)
	dcid := make([]byte, 8, 8)
	rand.Read(scid)
	rand.Read(dcid)

	var network string
	if useIPv6 {
		network = "udp6"
	} else {
		network = "udp4"
	}

	udpAddr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		return nil, err
	}
	udpConn, err := EstablishUDPConnection(udpAddr)
	if err != nil {
		return nil, err
	}

	c := NewConnection(serverName, QuicVersion, QuicALPNToken, scid, dcid, udpConn, resumptionSecret)
	c.UseIPv6 = useIPv6
	c.Host = udpAddr
	return c, nil
}

func NewConnection(serverName string, version uint32, ALPN string, SCID []byte, DCID[]byte , udpConn *net.UDPConn, resumptionSecret []byte) *Connection {
	c := new(Connection)
	c.ServerName = serverName
	c.UdpConnection = udpConn
	c.SourceCID = SCID
	c.DestinationCID = DCID
	c.OriginalDestinationCID = DCID
	c.PacketNumber = make(map[PNSpace]uint64)
	c.PacketNumber[PNSpaceInitial] = 0
	c.PacketNumber[PNSpaceHandshake] = 0
	c.PacketNumber[PNSpaceAppData] = 0
	c.ackQueue = make(map[PNSpace][]uint64)
	c.ackQueue[PNSpaceInitial] = nil
	c.ackQueue[PNSpaceHandshake] = nil
	c.ackQueue[PNSpaceAppData] = nil
	c.retransmissionBuffer = make(map[PNSpace]map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceInitial] = make(map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceHandshake] = make(map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceAppData] = make(map[uint64]RetransmittableFrames)

	c.RetransmissionTicker = time.NewTicker(100 * time.Millisecond)  // Dumb retransmission mechanism

	if !c.DisableIncPacketChan {
		c.IncomingPackets = make(chan Packet)

		go func() {
			for {
				packets, err, _ := c.ReadNextPackets()
				if err != nil {
					close(c.IncomingPackets)
					break
				}
				for _, p := range packets {
					c.IncomingPackets <- p
				}
			}
		}()
	}

	go func() {
		for range c.RetransmissionTicker.C {
			if c.DisableRetransmits {
				continue
			}
			var frames RetransmitBatch
			for _, buffer := range c.retransmissionBuffer {
				for k, v := range buffer {
					if time.Now().Sub(v.Timestamp).Nanoseconds() > 500e6 {
						frames = append(frames, v)
						delete(buffer, k)
					}
				}
			}

			c.RetransmitFrames(frames)
		}
	}()

	c.TransitionTo(version, ALPN, resumptionSecret)

	return c
}