package masterthesis

import (
	"bytes"
	"encoding/binary"
	"io"
	"github.com/davecgh/go-spew/spew"
)

type Acknowledger interface {
	ShouldBeAcknowledged() bool // Indicates whether or not the packet type should be acknowledged by the mean of sending an ack
}

type PacketEncoder interface {
	encodeHeader() []byte
	encodePayload() []byte
	encode([]byte) []byte
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
func (p abstractPacket) encode(payload []byte) []byte {
	buffer := new(bytes.Buffer)
	buffer.Write(p.encodeHeader())
	buffer.Write(payload)
	return buffer.Bytes()
}

type VersionNegotationPacket struct {
	abstractPacket
	SupportedVersions []SupportedVersion
}
type SupportedVersion uint32
func (p VersionNegotationPacket) ShouldBeAcknowledged() bool { return false }
func (p VersionNegotationPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, version := range p.SupportedVersions {
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
		p.SupportedVersions = append(p.SupportedVersions, SupportedVersion(version))
	}
	return p
}
func NewVersionNegotationPacket(versions []SupportedVersion, conn *Connection) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.header = NewLongHeader(VersionNegotiation, conn)
	p.SupportedVersions = versions
	return p
}

type ClientInitialPacket struct {
	abstractPacket
	streamFrames []StreamFrame
	padding      []PaddingFrame
}
func (p ClientInitialPacket) ShouldBeAcknowledged() bool { return true }
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
func (p ServerCleartextPacket) ShouldBeAcknowledged() bool { return len(p.streamFrames) > 0 }  // TODO: A padding only packet should be flagged somewhere
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
			p.ackFrames = append(p.ackFrames, *ReadAckFrame(buffer))
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
func (p ClientCleartextPacket) ShouldBeAcknowledged() bool { return len(p.streamFrames) > 0 }
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
	Frames []Frame
}
func (p *ProtectedPacket) ShouldBeAcknowledged() bool {
	for _, frame := range p.Frames {
		if _, ok :=  frame.(AckFrame); !ok {
			return true
		}
	}
	return false
}
func (p *ProtectedPacket) encodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.Frames {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadProtectedPacket(buffer *bytes.Reader, conn *Connection) *ProtectedPacket {
	p := new(ProtectedPacket)
	p.header = ReadHeader(buffer, conn)
	for {
		frame := NewFrame(buffer, conn)
		spew.Dump(frame)
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}
func NewProtectedPacket(conn *Connection) *ProtectedPacket {  // TODO: Figure out the short header 1RTT variant
	p := new(ProtectedPacket)
	p.header = NewLongHeader(OneRTTProtectedKP0, conn)
	return p
}