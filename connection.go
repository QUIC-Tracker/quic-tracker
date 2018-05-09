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
	"encoding/binary"
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
)

type Connection struct {
	ServerName    string
	UdpConnection *net.UDPConn
	Tls           *pigotls.Connection
	TLSTPHandler  *TLSTransportParameterHandler

	Cleartext        *CryptoState
	Protected        *CryptoState
	ZeroRTTprotected *CryptoState

	ReceivedPacketHandler func([]byte)
	SentPacketHandler     func([]byte)

	Streams              map[uint64]*Stream
	SourceCID            ConnectionID
	DestinationCID       ConnectionID
	PacketNumber         uint64
	ExpectedPacketNumber uint64
	Version              uint32
	omitConnectionId     bool
	ackQueue             []uint64 // Stores the packet numbers to be acked
	retransmissionBuffer map[uint64]RetransmittableFrames
	RetransmissionTicker *time.Ticker
	IgnorePathChallenge   bool
	DisableRetransmits    bool

	UseIPv6        bool
	Host           *net.UDPAddr
	ClientRandom   []byte
	ExporterSecret []byte
}
func (c *Connection) ConnectedIp() net.Addr {
	return c.UdpConnection.RemoteAddr()
}
func (c *Connection) nextPacketNumber() uint64 {
	c.PacketNumber++
	return c.PacketNumber
}
func (c *Connection) RetransmitFrames(frames RetransmitBatch) {  // TODO: Split in smaller packets if needed
	sort.Sort(frames)
	for _, f := range frames {
		if c.Protected != nil {
			packet := NewProtectedPacket(c)
			packet.Frames = f.Frames
			c.SendProtectedPacket(packet)
		} else if f.IsInitial {
			packet := NewInitialPacket(c)
			packet.Frames = f.Frames
			c.SendHandshakeProtectedPacket(packet)
		} else {
			packet := NewHandshakePacket(c)
			packet.Frames = f.Frames
			c.SendHandshakeProtectedPacket(packet)
		}
	}
}
func (c *Connection) SendFrames(frames []Frame) {
	if c.Protected != nil {
		packet := NewProtectedPacket(c)
		packet.Frames = frames
		c.SendProtectedPacket(packet)
	} else {
		packet := NewHandshakePacket(c)
		packet.Frames = frames
		c.SendHandshakeProtectedPacket(packet)
	}
}
func (c *Connection) SendHandshakeProtectedPacket(packet Packet) {
	if framePacket, ok := packet.(Framer); ok && len(framePacket.GetRetransmittableFrames()) > 0 {
		fullPacketNumber := (c.PacketNumber & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())
		batch := NewRetransmittableFrames(framePacket.GetRetransmittableFrames())
		_, batch.IsInitial = framePacket.(*InitialPacket)
		c.retransmissionBuffer[fullPacketNumber] = *batch
	}

	payload := packet.EncodePayload()
	lHeader := packet.Header().(*LongHeader)
	lHeader.PayloadLength = uint64(len(payload) + c.Cleartext.Write.Overhead())

	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.Encode(packet.EncodePayload()))
	}

	header := packet.EncodeHeader()
	protectedPayload := c.Cleartext.Write.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), payload, header)
	c.UdpConnection.Write(append(header, protectedPayload...))
}
func (c *Connection) SendProtectedPacket(packet Packet) {
	c.sendProtectedPacket(packet, c.Protected.Write)
}
func (c *Connection) SendZeroRTTProtectedPacket(packet Packet) {
	c.sendProtectedPacket(packet, c.ZeroRTTprotected.Write)
}
func (c *Connection) sendProtectedPacket(packet Packet, cipher cipher.AEAD) {
	if framePacket, ok := packet.(Framer); ok && len(framePacket.GetRetransmittableFrames()) > 0 {
		c.retransmissionBuffer[(c.PacketNumber & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())] = *NewRetransmittableFrames(framePacket.GetRetransmittableFrames())
	}

	payload := packet.EncodePayload()
	if lHeader, ok := packet.Header().(*LongHeader); ok {
		lHeader.PayloadLength = uint64(len(payload) + cipher.Overhead())
	}

	if c.SentPacketHandler != nil {
		c.SentPacketHandler(packet.Encode(packet.EncodePayload()))
	}

	header := packet.EncodeHeader()
	protectedPayload := cipher.Seal(nil, EncodeArgs(packet.Header().PacketNumber()), payload, header)
	c.UdpConnection.Write(append(header, protectedPayload...))
}
func (c *Connection) GetInitialPacket() *InitialPacket {
	extensionData, err := c.TLSTPHandler.GetExtensionData()
	if err != nil {
		println(err)
		return nil
	}
	c.Tls.SetQUICTransportParameters(extensionData)

	handshakeResult, notComplete, err := c.Tls.InitiateHandshake()
	if err != nil || !notComplete {
		println(err.Error())
		return nil
	}
	c.ClientRandom = make([]byte, 32, 32)
	copy(c.ClientRandom, handshakeResult[11:11+32])
	handshakeFrame := NewStreamFrame(0, c.Streams[0], handshakeResult, false)

	var initialLength int
	if c.UseIPv6 {
		initialLength = MinimumInitialLengthv6
	} else {
		initialLength = MinimumInitialLength
	}

	initialPacket := NewInitialPacket(c)
	initialPacket.Frames = append(initialPacket.Frames, handshakeFrame)
	paddingLength := initialLength - (initialPacket.header.Length() + len(initialPacket.EncodePayload()) + c.Cleartext.Write.Overhead())
	for i := 0; i < paddingLength; i++ {
		initialPacket.Frames = append(initialPacket.Frames, new(PaddingFrame))
	}

	return initialPacket
}

func (c *Connection) ProcessServerHello(packet Framer) (bool, Framer, error) { // Returns whether or not the TLS Handshake should continue
	if c.ZeroRTTprotected == nil {
		lHeader := packet.Header().(*LongHeader)
		c.DestinationCID = lHeader.SourceCID  // see https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.6
		if packet.Header().PacketType() == Retry {
			c.Streams = make(map[uint64]*Stream)
			c.Streams[0] = new(Stream)
			c.Cleartext = NewCleartextSaltedCryptoState(c)
			c.retransmissionBuffer = make(map[uint64]RetransmittableFrames)
			c.ackQueue = nil
		}
	}

	var serverData []byte
	for _, frame := range packet.GetFrames() {
		if streamFrame, ok := frame.(*StreamFrame); ok {
			serverData = append(serverData, streamFrame.StreamData...)
		}
	}

	var responsePacket Framer
	defer func() {if c.ackQueue != nil {responsePacket.AddFrame(c.GetAckFrame())}}()

	if len(serverData) > 0 {
		switch packet.(type) {
		case *HandshakePacket:
			responsePacket = NewHandshakePacket(c)
		case *RetryPacket:
			responsePacket = NewInitialPacket(c)
			defer func() {
				var initialLength int
				if c.UseIPv6 {
					initialLength = MinimumInitialLengthv6
				} else {
					initialLength = MinimumInitialLength
				}
				paddingLength := initialLength - (responsePacket.Header().Length() + len(responsePacket.EncodePayload()) + c.Cleartext.Write.Overhead())
				for i := 0; i < paddingLength; i++  {
					responsePacket.AddFrame(new(PaddingFrame))
				}
			}()
		}

		tlsData, notCompleted, err := c.Tls.Input(serverData)

		if err != nil {
			return notCompleted, responsePacket, err
		}

		if tlsData != nil && len(tlsData) > 0 {
			responsePacket.AddFrame(NewStreamFrame(0, c.Streams[0], tlsData, false))
		}

		if !notCompleted {
			c.Protected = NewProtectedCryptoState(c.Tls)
			c.ExporterSecret = c.Tls.ExporterSecret()

			// TODO: Export secret if completed
			// TODO: Check negotiated ALPN ?

			err = c.TLSTPHandler.ReceiveExtensionData(c.Tls.ReceivedQUICTransportParameters())
			if err != nil {
				return false, responsePacket, err
			}
		}
		return notCompleted, responsePacket,  nil
	} else {
		responsePacket = NewHandshakePacket(c)
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
	saveCleartext := func (ct []byte) {if c.ReceivedPacketHandler != nil {c.ReceivedPacketHandler(ct)}}

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
			saveCleartext(rec)
			off = len(rec)

			packets = append(packets, packet)
		} else {
			hLen := header.Length()
			var data []byte
			switch header.PacketType() {
			case Handshake, Initial, Retry:
				longHeader := header.(*LongHeader)
				pLen := int(longHeader.PayloadLength)

				payload, err := c.Cleartext.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[off+hLen:off+hLen+pLen], rec[off:off+hLen])
				if err != nil {
					return packets, err, rec
				}
				data = append(append(data, rec[off:off+hLen]...), payload...)
				off += hLen + pLen
			case OneBytePacketNumber, TwoBytesPacketNumber, FourBytesPacketNumber:  // Packets with a short header always include a 1-RTT protected payload.
				if c.Protected == nil {
					println("Crypto state is not ready to decrypt protected packets")
					return c.ReadNextPackets() // Packet may have been reordered, TODO: Implement a proper packet queue instead of triggering retransmissions
				}
				payload, err := c.Protected.Read.Open(nil, EncodeArgs(header.PacketNumber()), rec[off+hLen:], rec[off:off+hLen])
				if err != nil {
					return packets, err, rec
				}
				data = append(append(data, rec[off:off+hLen]...), payload...)
				off = len(rec)
			default:
				spew.Dump(header)
				return packets, errors.New("unknown packet type"), rec
			}

			saveCleartext(data)
			buffer := bytes.NewReader(data)

			switch header.PacketType() {
			case Handshake:
				packet = ReadHandshakePacket(buffer, c)
			case OneBytePacketNumber, TwoBytesPacketNumber, FourBytesPacketNumber:
				packet = ReadProtectedPacket(buffer, c)
			case Initial:
				packet = ReadInitialPacket(buffer, c)
			case Retry:
				packet = ReadRetryPacket(buffer, c)
			}

			fullPacketNumber := (c.ExpectedPacketNumber & 0xffffffff00000000) | uint64(packet.Header().PacketNumber())

			for _, number := range c.ackQueue {
				if number == fullPacketNumber  {
					fmt.Fprintf(os.Stderr, "Received duplicate packet number %d\n", fullPacketNumber)
					spew.Dump(packet)
					return c.ReadNextPackets()
					// TODO: Should it be acked again ?
				}
			}
			c.ackQueue = append(c.ackQueue, fullPacketNumber)
			c.ExpectedPacketNumber = fullPacketNumber + 1

			if framePacket, ok := packet.(Framer); ok {
				for _, f := range framePacket.GetFrames() {
					if ack, ok := f.(*AckFrame); ok {
						c.RetransmitFrames(c.ProcessAck(ack))
					}
				}

				if pathChallenge := framePacket.GetFirst(PathChallengeType); !c.IgnorePathChallenge && pathChallenge != nil {
					c.SendFrames([]Frame{PathResponse{pathChallenge.(*PathChallenge).Data}})
				}
			}

			packets = append(packets, packet)
		}
	}

	return packets, nil, rec
}
func (c *Connection) GetAckFrame() *AckFrame { // Returns an ack frame based on the packet numbers received
	sort.Sort(PacketNumberQueue(c.ackQueue))
	packetNumbers := c.ackQueue
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
func (c *Connection) ProcessAck(ack *AckFrame) RetransmitBatch {
	var frames RetransmitBatch
	currentPacketNumber := ack.LargestAcknowledged
	delete(c.retransmissionBuffer, currentPacketNumber)
	for i := uint64(0); i < ack.AckBlocks[0].block; i++ {
		currentPacketNumber--
		delete(c.retransmissionBuffer, currentPacketNumber)
	}
	for _, ackBlock := range ack.AckBlocks[1:] {
		for i := uint64(0); i <= ackBlock.gap; i++ {  // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			if f, ok := c.retransmissionBuffer[currentPacketNumber]; ok {
				frames = append(frames, f)
			}
			currentPacketNumber--
			delete(c.retransmissionBuffer, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.block; i++ {
			currentPacketNumber--
			delete(c.retransmissionBuffer, currentPacketNumber)
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
	c.Cleartext = NewCleartextSaltedCryptoState(c)
	c.Streams = make(map[uint64]*Stream)
	c.Streams[0] = &Stream{}
}
func (c *Connection) CloseConnection(quicLayer bool, errCode uint16, reasonPhrase string) {
	pkt := NewProtectedPacket(c)
	if quicLayer {
		pkt.Frames = append(pkt.Frames, ConnectionCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase})
	} else {
		pkt.Frames = append(pkt.Frames, ApplicationCloseFrame{errCode, uint64(len(reasonPhrase)), reasonPhrase})
	}
	c.SendProtectedPacket(pkt)
}
func (c *Connection) CloseStream(streamId uint64) {
	frame := *NewStreamFrame(streamId, c.Streams[streamId], nil, true)
	if c.Protected == nil {
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
	c.Streams[streamID] = new(Stream)

	streamFrame := NewStreamFrame(streamID, c.Streams[streamID], []byte(fmt.Sprintf("GET %s\r\n", path)), true)

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
	c.PacketNumber = binary.BigEndian.Uint64(c.SourceCID) & 0x7fffffff
	c.omitConnectionId = false
	c.retransmissionBuffer = make(map[uint64]RetransmittableFrames)

	c.RetransmissionTicker = time.NewTicker(100 * time.Millisecond)  // Dumb retransmission mechanism

	go func() {
		for range c.RetransmissionTicker.C {
			if c.DisableRetransmits {
				continue
			}
			var frames RetransmitBatch
			for k, v := range c.retransmissionBuffer {
				if time.Now().Sub(v.Timestamp).Nanoseconds() > 500e6 {
					frames = append(frames, v)
					delete(c.retransmissionBuffer, k)
				}
			}
			c.RetransmitFrames(frames)
		}
	}()

	c.TransitionTo(version, ALPN, resumptionSecret)

	return c
}