package main

import (
	"bytes"
	"encoding/binary"
	"io"
)

type Acknowledger interface {
	shouldBeAcknowledged() bool // Indicates whether or not the packet type should be acknowledged by the mean of sending an ack
}

type PacketEncoder interface {
	encodeHeader() []byte
	encodePayload() []byte
	encode() []byte
}

type Packet interface {
	Header() Header
	Acknowledger
	PacketEncoder
}

type abstractPacket struct {
	header Header
	Acknowledger
	PacketEncoder
}
func (p abstractPacket) Header() Header {
	return p.header
}
func (p abstractPacket) encodeHeader() []byte {
	return p.header.encode()
}
func (p abstractPacket) encode() []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(p.encodeHeader())
	buffer.Write(p.encodePayload())
	return buffer.Bytes()
}

type VersionNegotationPacket struct {
	abstractPacket
	supportedVersion []SupportedVersion
}
type SupportedVersion uint32
func (p VersionNegotationPacket) shouldBeAcknowledged() bool   { return false }
func (p VersionNegotationPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, version := range p.supportedVersion {
		binary.Write(buffer, binary.BigEndian, version)
	}
	return buffer.Bytes()
}
func ReadVersionNegotationPacket(buffer *bytes.Reader) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.header = ReadLongHeader(buffer)
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
func NewVersionNegotationPacket(versions []SupportedVersion, conn *Connection) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.header = NewLongHeader(VersionNegotiation, conn)
	p.supportedVersion = versions
	return p
}

type ClientInitialPacket struct {
	abstractPacket
	streamFrames []StreamFrame
	padding      []PaddingFrame
}
func (p ClientInitialPacket) shouldBeAcknowledged() bool   { return false }
func (p ClientInitialPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadClientInitialPacket(buffer *bytes.Reader, conn *Connection) *ClientInitialPacket {
	p := new(ClientInitialPacket)
	p.header = ReadLongHeader(buffer)
	for {
		typeByte, err := buffer.ReadByte()
		if err == io.EOF {
			break
		} else if err != nil {
			panic(err)
		}
		buffer.UnreadByte()
		if FrameType(typeByte) != PaddingFrameType {
			p.streamFrames = append(p.streamFrames, *ReadStreamFrame(buffer, conn))
		} else {
			p.padding = append(p.padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}
func NewClientInitialPacket(streamFrames []StreamFrame, padding []PaddingFrame, conn *Connection) *ClientInitialPacket {
	p := new(ClientInitialPacket)
	p.header = NewLongHeader(ClientInitial, conn)
	p.streamFrames = streamFrames
	p.padding = padding
	return p
}

type ServerStatelessRetryPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-5.4.2
}

type ServerCleartextPacket struct {
	abstractPacket
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p ServerCleartextPacket) shouldBeAcknowledged() bool   { return false }
func (p ServerCleartextPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.ackFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadServerCleartextPacket(buffer *bytes.Reader, conn *Connection) *ServerCleartextPacket {
	p := new(ServerCleartextPacket)
	p.header = ReadLongHeader(buffer)
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
			p.streamFrames = append(p.streamFrames, *ReadStreamFrame(buffer, conn))
		default:
			p.padding = append(p.padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}

type ClientCleartextPacket struct {
	abstractPacket
	streamFrames []StreamFrame
	ackFrames    []AckFrame
	padding      []PaddingFrame
}
func (p ClientCleartextPacket) shouldBeAcknowledged() bool   { return false }
func (p ClientCleartextPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.streamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.ackFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.padding {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func NewClientCleartextPacket(streamFrames []StreamFrame, ackFrames []AckFrame, padding []PaddingFrame, conn *Connection) *ClientCleartextPacket {
	p := new(ClientCleartextPacket)
	p.header = NewLongHeader(ClientCleartext, conn)
	p.streamFrames = streamFrames
	p.ackFrames = ackFrames
	p.padding = padding
	return p
}

type ProtectedPacket struct {
	abstractPacket
	frames []Frame
}
func (p *ProtectedPacket) shouldBeAcknowledged() bool   { return false } // TODO: Should they be ?
func (p *ProtectedPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.frames {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadProtectedPacket(buffer *bytes.Reader, conn *Connection) *ProtectedPacket {
	p := new(ProtectedPacket)
	p.header = ReadHeader(buffer)
	for {
		frame := NewFrame(buffer, conn)
		if frame == nil {
			break
		}
		p.frames = append(p.frames, frame)
	}
	return p
}