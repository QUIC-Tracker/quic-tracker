package main

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Packet interface {
	shouldBeAcknowledged() bool // Indicates whether or not the packet type should be acknowledged by the mean of sending an ack
	Encoder
}

type VersionNegotationPacket struct {
	header           *LongHeader
	supportedVersion []SupportedVersion
}
type SupportedVersion uint32
func (p *VersionNegotationPacket) shouldBeAcknowledged() bool   { return false }
func (p *VersionNegotationPacket) writeTo(buffer *bytes.Buffer) {
	p.header.writeTo(buffer)
	for _, version := range p.supportedVersion {
		binary.Write(buffer, binary.BigEndian, version)
	}
}
func NewVersionNegotationPacket(buffer *bytes.Reader) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.header = NewLongHeader(buffer)
	for {
		var version uint32
		err := binary.Read(buffer, binary.BigEndian, &version)
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		p.supportedVersion = append(p.supportedVersion, SupportedVersion(version))
	}
	return p
}

type CleartextPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.4
	header         *LongHeader
	integrityCheck uint64 // TODO: https://tools.ietf.org/html/draft-ietf-quic-tls-05#section-6.2
}
func (p *CleartextPacket) shouldBeAcknowledged() bool   { return false } // TODO: Should they be ?
func (p *CleartextPacket) writeTo(buffer *bytes.Buffer) {
	p.header.writeTo(buffer)
	binary.Write(buffer, binary.BigEndian, p.integrityCheck)
}
func NewCleartextPacket(buffer *bytes.Reader) *CleartextPacket {
	p := new(CleartextPacket)
	p.header = NewLongHeader(buffer)
	binary.Read(buffer, binary.BigEndian, p.integrityCheck)
	return p
}

type ClientInitialPacket struct {
	header       *LongHeader
	streamFrames []StreamFrame
	padding      []PaddingFrame
}
func (p *ClientInitialPacket) shouldBeAcknowledged() bool   { return false }
func (p *ClientInitialPacket) writeTo(buffer *bytes.Buffer) {
	p.header.writeTo(buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
}
func NewClientInitialPacket(buffer *bytes.Reader) *ClientInitialPacket {
	p := new(ClientInitialPacket)
	p.header = NewLongHeader(buffer)
	for {
		typeByte, err := buffer.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		buffer.UnreadByte()
		if FrameType(typeByte) != PaddingFrameType {
			p.streamFrames = append(p.streamFrames, *NewStreamFrame(buffer))
		} else {
			p.padding = append(p.padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}

type ServerStatelessRetryPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.4.2
}

type ServerCleartextPacket struct {
	header       *LongHeader
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p *ServerCleartextPacket) shouldBeAcknowledged() bool   { return false }
func (p *ServerCleartextPacket) writeTo(buffer *bytes.Buffer) {
	p.header.writeTo(buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.ackFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
}
func NewServerCleartextPacket(buffer *bytes.Reader) *ServerCleartextPacket {
	p := new(ServerCleartextPacket)
	p.header = NewLongHeader(buffer)
	for {
		typeByte, err := buffer.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		buffer.UnreadByte()
		switch {
		case 0xa0 <= typeByte && typeByte <= 0xbf:
			p.ackFrames = append(p.ackFrames, *NewAckFrame(buffer))
		case 0xc0 <= typeByte && typeByte <= 0xff:
			p.streamFrames = append(p.streamFrames, *NewStreamFrame(buffer))
		default:
			p.padding = append(p.padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}

type ClientCleartextPacket struct {
	header       LongHeader
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p *ClientCleartextPacket) shouldBeAcknowledged() bool   { return false }
func (p *ClientCleartextPacket) writeTo(buffer *bytes.Buffer) {
	p.header.writeTo(buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.ackFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
}

type ProtectedPacket struct {
	header *Header
	frames []Frame
}
func (p *ProtectedPacket) shouldBeAcknowledged() bool   { return false } // TODO: Should they be ?
func (p *ProtectedPacket) writeTo(buffer *bytes.Buffer) {
	for _, frame := range p.frames {
		frame.writeTo(buffer)
	}
}
func NewProtectedPacket(buffer *bytes.Reader) *ProtectedPacket {
	p := new(ProtectedPacket)
	p.header = NewHeader(buffer)
	for {
		frame := NewFrame(buffer)
		if frame == nil {
			break
		}
		p.frames = append(p.frames, frame)
	}
	return p
}