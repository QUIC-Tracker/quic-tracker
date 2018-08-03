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
	"log"
	"encoding/hex"
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

	CryptoStreams       CryptoStreams  // TODO: It should be a parent class without closing states
	Streams             Streams
	IncomingPackets     chan Packet
	IncomingPayloads    chan []byte // Contains the UDP payloads that are left to be decrypted. TODO: They should aged with each try and eventually be removed
	UnprocessedPayloads chan []byte // Contains the UDP payloads that cannot be decrypted because no sufficient crypto state exists

	OriginalDestinationCID ConnectionID
	SourceCID              ConnectionID
	DestinationCID         ConnectionID
	Version                uint32

	PacketNumber         map[PNSpace]uint64
	ExpectedPacketNumber map[PNSpace]uint64

	ackQueue             map[PNSpace][]uint64 // Stores the packet numbers to be acked
	retransmissionBuffer map[PNSpace]map[uint64]RetransmittableFrames
	RetransmissionTicker *time.Ticker
	Logger 				 *log.Logger

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
func (c *Connection) SendPacket(packet Packet, cipher cipher.AEAD, pnCipher *pigotls.Cipher) {
	switch packet.PNSpace() {
	case PNSpaceInitial, PNSpaceHandshake, PNSpaceAppData:
		c.Logger.Printf("Sending packet {type=%s, number=%d}\n", packet.Header().PacketType().String(), packet.Header().PacketNumber())

		if framePacket, ok := packet.(Framer); ok && len(framePacket.GetRetransmittableFrames()) > 0 {
			fullPacketNumber := (c.PacketNumber[packet.PNSpace()] & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())
			c.retransmissionBuffer[packet.PNSpace()][fullPacketNumber] = *NewRetransmittableFrames(framePacket.GetRetransmittableFrames(), packet.PNSpace())
		}

		payload := packet.EncodePayload()
		if h, ok := packet.Header().(*LongHeader); ok {
			h.PayloadLength = uint64(PacketNumberLen(h.packetNumber) + len(payload) + cipher.Overhead())
			h.LengthBeforePN = 6 + len(h.DestinationCID) + len(h.SourceCID) + int(VarIntLen(h.PayloadLength))
			if h.packetType == Initial {
				h.LengthBeforePN += int(VarIntLen(uint64(len(h.Token)))) + len(h.Token)
			}
		}

		header := packet.EncodeHeader()
		protectedPayload := cipher.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), payload, header)
		packetBytes := append(header, protectedPayload...)

		sample, sampleOffset := GetPacketSample(packet.Header(), packetBytes)

		copy(packetBytes[sampleOffset-4:sampleOffset], pnCipher.Encrypt(sample, packetBytes[sampleOffset-4:sampleOffset])[:PacketNumberLen(packet.Header().PacketNumber())])

		c.UdpConnection.Write(packetBytes)

		if c.SentPacketHandler != nil {
			c.SentPacketHandler(packet.Encode(packet.EncodePayload()), packet.Pointer())
		}
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
	cryptoFrame := NewCryptoFrame(c.CryptoStreams.Get(PNSpaceInitial), clientHello)

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

	cryptoStream := c.CryptoStreams.Get(packet.PNSpace())

	var handshakeData []byte

forLoop:
	for {
		select {
			case d := <- cryptoStream.ReadChan:
				handshakeData = append(handshakeData, d...)
			default:
				break forLoop
		}
	}

	var responsePacket Framer
	defer func() {
		if c.ackQueue[packet.PNSpace()] != nil && lHeader.PacketType() != Retry && packet.ShouldBeAcknowledged() {
			responsePacket.AddFrame(c.GetAckFrame(packet.PNSpace()))
	}}()

	switch packet.(type) {
	case Framer:
		if _, ok := packet.(*InitialPacket); ok {
			responsePacket = NewInitialPacket(c)
		} else if _, ok := packet.(*HandshakePacket); ok {
			responsePacket = NewHandshakePacket(c)
		} else if _, ok := packet.(*ProtectedPacket); ok {
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
				responsePacket.AddFrame(NewCryptoFrame(cryptoStream, responseData))
			}

			if c.HandshakeCrypto == nil {
				c.HandshakeCrypto = new(CryptoState)
			}

			if c.HandshakeCrypto != nil {
				if c.HandshakeCrypto.PacketRead == nil && len(c.Tls.HandshakeReadSecret()) > 0{
					c.Logger.Printf("Installing handshake read crypto with secret %s\n", hex.EncodeToString(c.Tls.HandshakeReadSecret()))
					c.HandshakeCrypto.InitRead(c.Tls, c.Tls.HandshakeReadSecret())
				}
				if c.HandshakeCrypto.PacketWrite == nil && len(c.Tls.HandshakeWriteSecret()) > 0 {
					c.Logger.Printf("Installing handshake write crypto with secret %s\n", hex.EncodeToString(c.Tls.HandshakeWriteSecret()))
					c.HandshakeCrypto.InitWrite(c.Tls, c.Tls.HandshakeWriteSecret())
					spew.Dump(c.Tls.HandshakeWriteSecret())
				}
			}

			if !notCompleted {
				c.Logger.Printf("Handshake has completed, installing protected crypto {read=%s, write=%s}\n", hex.EncodeToString(c.Tls.ProtectedReadSecret()), hex.EncodeToString(c.Tls.ProtectedWriteSecret()))
				c.ProtectedCrypto = NewProtectedCryptoState(c.Tls, c.Tls.ProtectedReadSecret(), c.Tls.ProtectedWriteSecret())
				c.ExporterSecret = c.Tls.ExporterSecret()

				// TODO: Check negotiated ALPN ?

				err = c.TLSTPHandler.ReceiveExtensionData(c.Tls.ReceivedQUICTransportParameters())
				if err != nil {
					c.Logger.Println("Failed to decode extension data")
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
		c.Logger.Println("No appropriate version was found in the VN packet")
		return errors.New("no appropriate version found")
	}
	QuicVersion, QuicALPNToken = version, fmt.Sprintf("hq-%02d", version & 0xff)
	c.TransitionTo(QuicVersion, QuicALPNToken, nil)
	return nil
}
func (c *Connection) ReadNextPackets() ([]Packet, error, []byte) {
	saveCleartext := func (ct []byte, p unsafe.Pointer) {if c.ReceivedPacketHandler != nil {c.ReceivedPacketHandler(ct, p)}}

	udpPayload := <- c.IncomingPayloads

	var packets []Packet
	var off int

outerLoop:
	for len(udpPayload) > off {
		packetBytes := udpPayload[off:]
		header := ReadHeader(bytes.NewReader(packetBytes), c)

		sample, sampleOffset := GetPacketSample(header, packetBytes)

		var cryptoState *CryptoState = nil
		switch header.PacketType() {
		case Initial:
			cryptoState = c.InitialCrypto
		case Handshake:
			cryptoState = c.HandshakeCrypto
		case ZeroRTTProtected:
			cryptoState = c.ZeroRTTCrypto
		case ShortHeaderPacket:
			cryptoState = c.ProtectedCrypto
		}

		var pnLength int

		switch header.PacketType() {
		case Initial, Handshake, ZeroRTTProtected, ShortHeaderPacket:
			if cryptoState != nil && cryptoState.PacketRead != nil && cryptoState.Read != nil {
				c.Logger.Printf("Decrypting packet number of %s packet of length %d bytes", header.PacketType().String(), len(packetBytes))
				pn := cryptoState.PacketRead.Encrypt(sample, packetBytes[sampleOffset-4:sampleOffset])
				pnbuf := bytes.NewReader(pn)
				DecodePacketNumber(pnbuf)
				pnLength = len(pn) - pnbuf.Len()
				copy(packetBytes[sampleOffset-4:sampleOffset], pn[:pnLength])
				header = ReadHeader(bytes.NewReader(packetBytes), c) // Update packet number
			} else {
				c.Logger.Printf("Packet number of %s packet of length %d bytes could not be decrypted, putting it back in the buffer\n", header.PacketType().String(), len(packetBytes))
				c.UnprocessedPayloads <- packetBytes
				break outerLoop
			}
		}

		c.Logger.Printf("Successfully decrypted header {type=%s, number=%d}\n", header.PacketType().String(), header.PacketNumber())

		var packet Packet

		if lHeader, ok := header.(*LongHeader); ok && lHeader.Version == 0x00000000 {
			packet = ReadVersionNegotationPacket(bytes.NewReader(udpPayload))
			for k := range c.retransmissionBuffer {
				delete(c.retransmissionBuffer, k)
			}
			saveCleartext(udpPayload, packet.Pointer())
			off = len(udpPayload)

			packets = append(packets, packet)
		} else {
			hLen := header.Length()
			var data []byte
			switch header.PacketType() {
			case Handshake, Initial:
				longHeader := header.(*LongHeader)
				pLen := int(longHeader.PayloadLength) - pnLength

				c.Logger.Printf("Decrypt op: {off=%d, hLen=%d, pLen=%d, len(udpPayload)=%d}\n", off, hLen, pLen, len(udpPayload))
				payload, err := cryptoState.Read.Open(nil, EncodeArgs(header.PacketNumber()), udpPayload[off+hLen:off+hLen+pLen], udpPayload[off:off+hLen])
				if err != nil {
					c.Logger.Printf("Could not decrypt packet {type=%s, number=%d}\n", header.PacketType().String(), header.PacketNumber())
					return packets, err, udpPayload
				}
				data = append(append(data, udpPayload[off:off+hLen]...), payload...)
				off += hLen + pLen
			case ShortHeaderPacket:  // Packets with a short header always include a 1-RTT protected payload.
				payload, err := c.ProtectedCrypto.Read.Open(nil, EncodeArgs(header.PacketNumber()), udpPayload[off+hLen:], udpPayload[off:off+hLen])
				if err != nil {
					c.Logger.Printf("Could not decrypt packet {type=%s, number=%d}\n", header.PacketType().String(), header.PacketNumber())
					return packets, err, udpPayload
				}
				data = append(append(data, udpPayload[off:off+hLen]...), payload...)
				off = len(udpPayload)
			case Retry:
				panic("TODO PR#1498")
			default:
				spew.Dump(header)
				return packets, errors.New("unknown packet type"), udpPayload
			}

			c.Logger.Printf("Successfully unprotected packet {type=%s, number=%d}\n", header.PacketType().String(), header.PacketNumber())

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

			c.Logger.Printf("Successfully parsed packet {type=%s, number=%d, length=%d}\n", header.PacketType().String(), header.PacketNumber(), int(buffer.Size()) - buffer.Len())

			saveCleartext(data, packet.Pointer())

			if packet.PNSpace() != PNSpaceNoSpace {
				fullPacketNumber := (c.ExpectedPacketNumber[packet.PNSpace()] & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())

				for _, number := range c.ackQueue[packet.PNSpace()] {
					if number == fullPacketNumber {
						c.Logger.Printf("Received duplicate packet number %d in PN space %s\n", fullPacketNumber, packet.PNSpace().String())
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

	return packets, nil, udpPayload
}
func (c *Connection) GetAckFrame(space PNSpace) *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.ackQueue[space]))
	packetNumbers := c.ackQueue[space]
	if len(packetNumbers) == 0 {
		return nil
	}
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
	c.ExpectedPacketNumber = make(map[PNSpace]uint64)
	c.ExpectedPacketNumber[PNSpaceInitial] = 0
	c.ExpectedPacketNumber[PNSpaceHandshake] = 0
	c.ExpectedPacketNumber[PNSpaceAppData] = 0
	c.ackQueue = make(map[PNSpace][]uint64)
	c.ackQueue[PNSpaceInitial] = nil
	c.ackQueue[PNSpaceHandshake] = nil
	c.ackQueue[PNSpaceAppData] = nil
	c.retransmissionBuffer = make(map[PNSpace]map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceInitial] = make(map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceHandshake] = make(map[uint64]RetransmittableFrames)
	c.retransmissionBuffer[PNSpaceAppData] = make(map[uint64]RetransmittableFrames)
	c.CryptoStreams = make(map[PNSpace]*Stream)

	c.RetransmissionTicker = time.NewTicker(100 * time.Millisecond)  // Dumb retransmission mechanism

	c.Logger = log.New(os.Stdout, fmt.Sprintf("[CID %s] ", hex.EncodeToString(c.SourceCID)), log.LstdFlags | log.Lshortfile)

	if !c.DisableIncPacketChan {
		c.IncomingPackets = make(chan Packet)

		go func() {
			for {
				packets, err, _ := c.ReadNextPackets()
				if err != nil {
					c.Logger.Println("Closing IncomingPackets channels due to error:", err.Error())
					close(c.IncomingPackets)
					break
				}
				for _, p := range packets {
					c.Logger.Println("Received packet")
					spew.Dump(p)
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
			if len(frames) > 0 {
				c.Logger.Printf("Retransmitting %d frames\n", len(frames))
			}
			c.RetransmitFrames(frames)
		}
	}()

	recChan := make(chan []byte)
	go func() {
		for {
			recBuf := make([]byte, MaxUDPPayloadSize)
			i, _, err := c.UdpConnection.ReadFromUDP(recBuf)
			if err != nil {
				c.Logger.Println("Closing UDP socket because of error", err.Error())
				close(recChan)
				break
			}
			c.Logger.Printf("Received %d bytes from UDP socket\n", i)
			payload := make([]byte, i)
			copy(payload, recBuf[:i])
			recChan <- payload
		}
	}()

	c.IncomingPayloads = make(chan []byte, 1000)
	c.UnprocessedPayloads = make(chan []byte, 1000)

	go func() {
		isRecChanClosed := false
		for {
			if isRecChanClosed {
				p := <- c.UnprocessedPayloads
				c.IncomingPayloads <- p
				c.Logger.Printf("Put back an %d-byte payload in to the ring buffer\n", len(p))
			} else {
				select {
				case p := <-c.UnprocessedPayloads:
					c.IncomingPayloads <- p
					c.Logger.Printf("Put back an %d-byte payload in to the ring buffer\n", len(p))
				case payload := <-recChan:
					if payload != nil {
					forLoop:
						for {
							select {
							case p := <-c.UnprocessedPayloads:
								c.IncomingPayloads <- p
								c.Logger.Printf("Put back an %d-byte payload in to the ring buffer\n", len(p))
							case c.IncomingPayloads <- payload:
								c.Logger.Printf("Put an %d-byte payload in to the ring buffer\n", len(payload))
								break forLoop
							}
						}
					} else {
						isRecChanClosed = true
					}
				}
			}
		}
	}()

	c.TransitionTo(version, ALPN, resumptionSecret)

	return c
}