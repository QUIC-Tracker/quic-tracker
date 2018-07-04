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
	"bytes"
	"encoding/binary"
	"io"
	"github.com/davecgh/go-spew/spew"
	"unsafe"
)

type Acknowledger interface {
	ShouldBeAcknowledged() bool // Indicates whether or not the packet type should be acknowledged by the mean of sending an ack
}

type PacketEncoder interface {
	EncodeHeader() []byte
	EncodePayload() []byte
	Encode([]byte) []byte
}

type Packet interface {
	Header() Header
	Acknowledger
	PacketEncoder
	Pointer() unsafe.Pointer
}

type abstractPacket struct {
	header Header
	Acknowledger
	PacketEncoder
}
func (p abstractPacket) Header() Header {
	return p.header
}
func (p abstractPacket) EncodeHeader() []byte {
	return p.header.Encode()
}
func (p abstractPacket) Encode(payload []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(p.EncodeHeader())
	buffer.Write(payload)
	return buffer.Bytes()
}

type VersionNegotationPacket struct {
	abstractPacket
	UnusedField uint8
	Version        uint32
	DestinationCID ConnectionID
	SourceCID      ConnectionID
	SupportedVersions []SupportedVersion
}
type SupportedVersion uint32
func (p *VersionNegotationPacket) ShouldBeAcknowledged() bool { return false }
func (p *VersionNegotationPacket) EncodePayload() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(p.UnusedField & 0x80)
	binary.Write(buffer, binary.BigEndian, p.Version)
	buffer.WriteByte((p.DestinationCID.CIDL() << 4) | p.SourceCID.CIDL())
	binary.Write(buffer, binary.BigEndian, p.DestinationCID)
	binary.Write(buffer, binary.BigEndian, p.SourceCID)
	for _, version := range p.SupportedVersions {
		binary.Write(buffer, binary.BigEndian, version)
	}
	return buffer.Bytes()
}
func (p *VersionNegotationPacket) Pointer() unsafe.Pointer {
	return unsafe.Pointer(p)
}
func ReadVersionNegotationPacket(buffer *bytes.Reader) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	b, err := buffer.ReadByte()
	if err != nil {
		panic(err)
	}
	p.UnusedField = b & 0x7f
	binary.Read(buffer, binary.BigEndian, &p.Version)
	CIDL, _ := buffer.ReadByte()
	DCIL := 3 + ((CIDL & 0xf0) >> 4)
	SCIL := 3 + (CIDL & 0xf)
	p.DestinationCID = make([]byte, DCIL, DCIL)
	binary.Read(buffer, binary.BigEndian, &p.DestinationCID)
	p.SourceCID = make([]byte, SCIL, SCIL)
	binary.Read(buffer, binary.BigEndian, &p.SourceCID)
	for {
		var version uint32
		err := binary.Read(buffer, binary.BigEndian, &version)
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		p.SupportedVersions = append(p.SupportedVersions, SupportedVersion(version))
	}
	return p
}
func NewVersionNegotationPacket(unusedField uint8, version uint32, versions []SupportedVersion, conn *Connection) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.UnusedField = unusedField
	p.DestinationCID = conn.DestinationCID
	p.SourceCID = conn.SourceCID
	p.Version = version
	p.SupportedVersions = versions
	return p
}

type Framer interface {
	Packet
	GetFrames() []Frame
	AddFrame(frame Frame)
	GetRetransmittableFrames() []Frame
	Contains(frameType FrameType) bool
	GetFirst(frameType FrameType) Frame
}
type FramePacket struct {
	abstractPacket
	Frames []Frame
}
func (p *FramePacket) GetFrames() []Frame {
	return p.Frames
}
func (p *FramePacket) AddFrame(frame Frame) {
	p.Frames = append(p.Frames, frame)
}
func (p *FramePacket) GetRetransmittableFrames() []Frame {
	var frames []Frame
	for _, frame := range p.Frames {
		if frame.shouldBeRetransmitted() {
			frames = append(frames, frame)
		}
	}
	return frames
}
func (p *FramePacket) Pointer() unsafe.Pointer {
	return unsafe.Pointer(p)
}
func (p *FramePacket) Contains(frameType FrameType) bool {
	for _, f := range p.Frames {
		if f.FrameType() == frameType {
			return true
		}
	}
	return false
}
func (p *FramePacket) GetFirst(frameType FrameType) Frame {
	for _, f := range p.Frames {
		if f.FrameType() == frameType {
			return f
		}
	}
	return nil
}
func (p *FramePacket) ShouldBeAcknowledged() bool {
	for _, frame := range p.Frames {
		switch frame.(type) {
		case *AckFrame, *PaddingFrame, *ConnectionCloseFrame, *ApplicationCloseFrame:
		default:
			return true
		}
	}
	return false
}
func (p *FramePacket) EncodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.Frames {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}

type InitialPacket struct {
	FramePacket
}
func (p InitialPacket) GetRetransmittableFrames() []Frame {
	return p.Frames
}
func ReadInitialPacket(buffer *bytes.Reader, conn *Connection) *InitialPacket {
	p := new(InitialPacket)
	p.header = ReadLongHeader(buffer)
	for {
		frame, err := NewFrame(buffer, conn)
		if err != nil {
			spew.Dump(p)
			panic(err)
		}
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}
func NewInitialPacket(conn *Connection) *InitialPacket {
	p := new(InitialPacket)
	p.header = NewLongHeader(Initial, conn)
	return p
}

type RetryPacket struct {
	FramePacket
}
func ReadRetryPacket(buffer *bytes.Reader, conn *Connection) *RetryPacket {
	p := new(RetryPacket)
	p.header = ReadLongHeader(buffer)
	for {
		frame, err := NewFrame(buffer, conn)
		if err != nil {
			spew.Dump(p)
			panic(err)
		}
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}

type HandshakePacket struct {
	FramePacket
}
func ReadHandshakePacket(buffer *bytes.Reader, conn *Connection) *HandshakePacket {
	p := new(HandshakePacket)
	p.header = ReadLongHeader(buffer)
	for {
		frame, err := NewFrame(buffer, conn)
		if err != nil {
			spew.Dump(p)
			panic(err)
		}
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}
func NewHandshakePacket(conn *Connection) *HandshakePacket {
	p := new(HandshakePacket)
	p.header = NewLongHeader(Handshake, conn)
	return p
}

type ProtectedPacket struct {
	FramePacket
}
func ReadProtectedPacket(buffer *bytes.Reader, conn *Connection) *ProtectedPacket {
	p := new(ProtectedPacket)
	p.header = ReadHeader(buffer, conn)
	for {
		frame, err := NewFrame(buffer, conn)
		if err != nil {
			spew.Dump(p)
			panic(err)
		}
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}
func NewProtectedPacket(conn *Connection) *ProtectedPacket {
	p := new(ProtectedPacket)
	p.header = NewShortHeader(FourBytesPacketNumber, KeyPhaseZero, conn)
	return p
}

type ZeroRTTProtectedPacket struct {
	FramePacket
}
func NewZeroRTTProtectedPacket(conn *Connection) *ZeroRTTProtectedPacket {
	p := new(ZeroRTTProtectedPacket)
	p.header = NewLongHeader(ZeroRTTProtected, conn)
	return p
}