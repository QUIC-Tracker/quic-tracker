package masterthesis

import (
	"bytes"
	"encoding/binary"
	"io"
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
	return p.header.encode()
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
	ConnectionId uint64
	Version SupportedVersion
	SupportedVersions []SupportedVersion
}
type SupportedVersion uint32
func (p VersionNegotationPacket) ShouldBeAcknowledged() bool { return false }
func (p VersionNegotationPacket) EncodePayload() []byte {
	buffer := new(bytes.Buffer)
	buffer.WriteByte(p.UnusedField & 0x80)
	binary.Write(buffer, binary.BigEndian, p.ConnectionId)
	binary.Write(buffer, binary.BigEndian, p.Version)
	for _, version := range p.SupportedVersions {
		binary.Write(buffer, binary.BigEndian, version)
	}
	return buffer.Bytes()
}
func ReadVersionNegotationPacket(buffer *bytes.Reader) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	b, err := buffer.ReadByte()
	if err != nil {
		panic(err)
	}
	p.UnusedField = b & 0x7f
	binary.Read(buffer, binary.BigEndian, &p.ConnectionId)
	binary.Read(buffer, binary.BigEndian, &p.Version)
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
func NewVersionNegotationPacket(unusedField uint8, version SupportedVersion, versions []SupportedVersion, conn *Connection) *VersionNegotationPacket {
	p := new(VersionNegotationPacket)
	p.UnusedField = unusedField
	p.Version = version
	p.SupportedVersions = versions
	return p
}

type InitialPacket struct {
	abstractPacket
	StreamFrames []StreamFrame
	Padding      []PaddingFrame
}
func (p InitialPacket) ShouldBeAcknowledged() bool { return true }
func (p InitialPacket) EncodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.StreamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.Padding {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadInitialPacket(buffer *bytes.Reader, conn *Connection) *InitialPacket {
	p := new(InitialPacket)
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
			p.StreamFrames = append(p.StreamFrames, *ReadStreamFrame(buffer, conn))
		} else {
			p.Padding = append(p.Padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}
func NewInitialPacket(streamFrames []StreamFrame, padding []PaddingFrame, conn *Connection) *InitialPacket {
	p := new(InitialPacket)
	p.header = NewLongHeader(Initial, conn)
	p.StreamFrames = streamFrames
	p.Padding = padding
	return p
}

type RetryPacket struct {
	// TODO: https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-5.4.2
}

type HandshakePacket struct {
	abstractPacket
	StreamFrames []StreamFrame
	AckFrames    []AckFrame
	Padding      []PaddingFrame
}
func (p HandshakePacket) ShouldBeAcknowledged() bool { return len(p.StreamFrames) > 0 } // TODO: A padding only packet should be flagged somewhere
func (p HandshakePacket) EncodePayload() []byte {
	buffer := new(bytes.Buffer)
	for _, frame := range p.StreamFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.AckFrames {
		frame.writeTo(buffer)
	}
	for _, frame := range p.Padding {
		frame.writeTo(buffer)
	}
	return buffer.Bytes()
}
func ReadHandshakePacket(buffer *bytes.Reader, conn *Connection) *HandshakePacket {
	p := new(HandshakePacket)
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
		case typeByte == 0x0e:
			p.AckFrames = append(p.AckFrames, *ReadAckFrame(buffer))
		case 0x10 <= typeByte && typeByte <= 0x17:
			p.StreamFrames = append(p.StreamFrames, *ReadStreamFrame(buffer, conn))
		default:
			p.Padding = append(p.Padding, *NewPaddingFrame(buffer))
		}
	}
	return p
}
func NewHandshakePacket(streamFrames []StreamFrame, ackFrames []AckFrame, padding []PaddingFrame, conn *Connection) *HandshakePacket {
	p := new(HandshakePacket)
	p.header = NewLongHeader(Handshake, conn)
	p.StreamFrames = streamFrames
	p.AckFrames = ackFrames
	p.Padding = padding
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
func (p *ProtectedPacket) EncodePayload() []byte {
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
		if frame == nil {
			break
		}
		p.Frames = append(p.Frames, frame)
	}
	return p
}
func NewProtectedPacket(conn *Connection) *ProtectedPacket {  // TODO: Figure out the short header 1RTT variant
	p := new(ProtectedPacket)
	p.header = NewLongHeader(ZeroRTTProtected, conn)
	return p
}