package quictracker

import (
	"bytes"
	"encoding/binary"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
)

type Header interface {
	PacketType() PacketType
	DestinationConnectionID() ConnectionID
	PacketNumber() uint32
	EncryptionLevel() EncryptionLevel
	Encode() []byte
	Length() int
}
func ReadHeader(buffer *bytes.Reader, conn *Connection) Header {
	var h Header
	typeByte, _ := buffer.ReadByte()
	buffer.UnreadByte()
	if typeByte & 0x80 == 0x80 {
		h = ReadLongHeader(buffer)
	} else {
		h = ReadShortHeader(buffer, conn)
	}
	return h
}

type LongHeader struct {
	packetType     PacketType
	Version        uint32
	DestinationCID ConnectionID
	SourceCID      ConnectionID
	PayloadLength  uint64
	Token		   []byte
	packetNumber   uint32
	LengthBeforePN int
	length         int
}
func (h *LongHeader) Encode() []byte {
	buffer := new(bytes.Buffer)
	typeByte := uint8(0x80)
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.Version)
	buffer.WriteByte((h.DestinationCID.CIDL() << 4) | h.SourceCID.CIDL())
	binary.Write(buffer, binary.BigEndian, h.DestinationCID)
	binary.Write(buffer, binary.BigEndian, h.SourceCID)
	if h.packetType == Initial {
		WriteVarInt(buffer, uint64(len(h.Token)))
		buffer.Write(h.Token)
	}
	WriteVarInt(buffer, h.PayloadLength)
	buffer.Write(EncodePacketNumber(h.packetNumber))
	return buffer.Bytes()
}
func (h *LongHeader) PacketType() PacketType { return h.packetType }
func (h *LongHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *LongHeader) PacketNumber() uint32 { return h.packetNumber }
func (h *LongHeader) EncryptionLevel() EncryptionLevel { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *LongHeader) Length() int { return h.length }
func ReadLongHeader(buffer *bytes.Reader) *LongHeader {
	h := new(LongHeader)
	h.length = buffer.Len()
	h.LengthBeforePN = buffer.Len()
	typeByte, _ := buffer.ReadByte()
	h.packetType = PacketType(typeByte - 0x80)
	binary.Read(buffer, binary.BigEndian, &h.Version)
	CIDL, _ := buffer.ReadByte()
	DCIL := 3 + ((CIDL & 0xf0) >> 4)
	SCIL := 3 + (CIDL & 0xf)
	h.DestinationCID = make([]byte, DCIL, DCIL)
	binary.Read(buffer, binary.BigEndian, &h.DestinationCID)
	h.SourceCID = make([]byte, SCIL, SCIL)
	binary.Read(buffer, binary.BigEndian, &h.SourceCID)
	if h.packetType == Initial {
		tokenLength, _ := ReadVarInt(buffer)
		h.Token = make([]byte, tokenLength)
		buffer.Read(h.Token)
	}
	h.PayloadLength, _ = ReadVarInt(buffer)
	h.LengthBeforePN -= buffer.Len()
	h.packetNumber = DecodePacketNumber(buffer)
	h.length -= buffer.Len()
	return h
}
func NewLongHeader(packetType PacketType, conn *Connection, space PNSpace) *LongHeader {
	h := new(LongHeader)
	h.packetType = packetType
	h.SourceCID = conn.SourceCID
	if packetType == ZeroRTTProtected {
		h.DestinationCID = conn.OriginalDestinationCID
	} else {
		h.DestinationCID = conn.DestinationCID
	}
	h.packetNumber = uint32(conn.nextPacketNumber(space))
	h.Version = conn.Version
	return h
}

type PacketType uint8

const (
	Initial          PacketType = 0x7f
	Retry            PacketType = 0x7e
	Handshake        PacketType = 0x7d
	ZeroRTTProtected PacketType = 0x7c

	ShortHeaderPacket PacketType = 0  // TODO: Find a way around this
)

var packetTypeToString = map[PacketType]string{
	Initial: "Initial",
	Retry: "Retry",
	Handshake: "Handshake",
	ZeroRTTProtected: "0-RTT Protected",

	ShortHeaderPacket: "1-RTT Protected",
}

func (t PacketType) String() string {
	return packetTypeToString[t]
}

type ShortHeader struct {
	KeyPhase       KeyPhaseBit
	DestinationCID ConnectionID
	packetNumber   uint32
	length 		   int
}
func (h *ShortHeader) Encode() []byte {
	buffer := new(bytes.Buffer)
	var typeByte uint8
	if h.KeyPhase == KeyPhaseOne {
		typeByte |= 0x40
	}
	typeByte |= 0x30
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.DestinationCID)
	buffer.Write(EncodePacketNumber(h.packetNumber))

	return buffer.Bytes()
}
func (h *ShortHeader) PacketType() PacketType { return ShortHeaderPacket }
func (h *ShortHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *ShortHeader) PacketNumber() uint32 { return h.packetNumber }
func (h *ShortHeader) EncryptionLevel() EncryptionLevel { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *ShortHeader) Length() int { return h.length }
func ReadShortHeader(buffer *bytes.Reader, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.length = buffer.Len()
	typeByte, _ := buffer.ReadByte()
	h.KeyPhase = (typeByte & 0x40) == 0x40

	if typeByte & 0x38 != 0x30 {
		fmt.Printf("SH fixed bits not respected: expected %b, got %b\n", 0x30, typeByte & 0x38)
	}

	h.DestinationCID = make([]byte, len(conn.SourceCID), len(conn.SourceCID))
	buffer.Read(h.DestinationCID)
	h.packetNumber = DecodePacketNumber(buffer)
	h.length -= buffer.Len()
	return h
}
func NewShortHeader(keyPhase KeyPhaseBit, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.KeyPhase = keyPhase
	h.DestinationCID = conn.DestinationCID
	h.packetNumber = uint32(conn.nextPacketNumber(PNSpaceAppData))
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true

func EncodePacketNumber(packetNumber uint32) []byte {
	if packetNumber <= 0x7f {
		return []byte{byte(packetNumber)}
	} else if packetNumber <= 0x3fff {
		return Uint16ToBEBytes(uint16(0x8000 | packetNumber))
	} else if packetNumber <= 0x3fffffff {
		return Uint32ToBEBytes(uint32(0xc0000000 | packetNumber))
	} else {
		panic("Could not encode packet number")
	}
}
func DecodePacketNumber(buffer *bytes.Reader) uint32 {
	firstByte, _ := buffer.ReadByte()
	if firstByte & 0x80 == 0 {
		return uint32(firstByte)
	} else if firstByte & 0xc0 == 0x80 {
		twoBytes := make([]byte, 2)
		buffer.UnreadByte()
		buffer.Read(twoBytes)
		return uint32(0x3fff & binary.BigEndian.Uint16(twoBytes))
	} else if firstByte & 0xc0 == 0xc0 {
		fourBytes := make([]byte, 4)
		buffer.UnreadByte()
		buffer.Read(fourBytes)
		return uint32(0x3fffffff & binary.BigEndian.Uint32(fourBytes))
	} else {
		panic("Could not decode packet number")
	}
}
func PacketNumberLen(packetNumber uint32) int {
	switch {
	case packetNumber <= 0x7f:
		return 1
	case packetNumber <= 0x3fff:
		return 2
	case packetNumber <= 0x3fffffff:
		return 4
	default:
		panic("could not determine packet number length")
	}
}