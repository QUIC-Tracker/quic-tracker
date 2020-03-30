package quictracker

import (
	"bytes"
	"encoding/binary"
)

type PacketType uint8

const (
	Initial          PacketType = 0x0
	ZeroRTTProtected PacketType = 0x1
	Handshake        PacketType = 0x2
	Retry            PacketType = 0x3

	VersionNegotiation PacketType = 0xfe // TODO: Find a way around this
	ShortHeaderPacket  PacketType = 0xff // TODO: Find a way around this
)

var packetTypeToString = map[PacketType]string{
	Initial: "Initial",
	Retry: "Retry",
	Handshake: "Handshake",
	ZeroRTTProtected: "0-RTT Protected",

	ShortHeaderPacket: "1-RTT Protected",
}

var packetTypeToPNSPace = map[PacketType]PNSpace {
	Initial: PNSpaceInitial,
	Retry: PNSpaceNoSpace,
	Handshake: PNSpaceHandshake,
	ZeroRTTProtected: PNSpaceAppData,

	ShortHeaderPacket: PNSpaceAppData,
}

type Header interface {
	PacketType() PacketType
	DestinationConnectionID() ConnectionID
	PacketNumber() PacketNumber
	TruncatedPN() TruncatedPN
	EncryptionLevel() EncryptionLevel
	Encode() []byte
	HeaderLength() int
}
func ReadHeader(buffer *bytes.Reader, conn *Connection) Header {
	var h Header
	typeByte, _ := buffer.ReadByte()
	buffer.UnreadByte()
	if typeByte & 0x80 == 0x80 {
		h = ReadLongHeader(buffer, conn)
	} else {
		h = ReadShortHeader(buffer, conn)
	}
	return h
}

type LongHeader struct {
	packetType     PacketType
	lowerBits      byte
	Version        uint32
	DestinationCID ConnectionID
	SourceCID      ConnectionID
	TokenLength    VarInt
	Token          []byte
	Length         VarInt
	packetNumber   PacketNumber
	truncatedPN    TruncatedPN
}
func (h *LongHeader) Encode() []byte {
	buffer := new(bytes.Buffer)
	typeByte := uint8(0xC0)
	typeByte |= uint8(h.packetType) << 4
	typeByte |= uint8(h.truncatedPN.Length) - 1
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.Version)
	buffer.WriteByte(h.DestinationCID.CIDL())
	binary.Write(buffer, binary.BigEndian, h.DestinationCID)
	buffer.WriteByte(h.SourceCID.CIDL())
	binary.Write(buffer, binary.BigEndian, h.SourceCID)
	if h.packetType == Initial {
		buffer.Write(h.TokenLength.Encode())
		buffer.Write(h.Token)
	}
	if h.packetType != Retry {
		buffer.Write(h.Length.Encode())
		buffer.Write(h.truncatedPN.Encode())
	}
	return buffer.Bytes()
}
func (h *LongHeader) PacketType() PacketType { return h.packetType }
func (h *LongHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *LongHeader) PacketNumber() PacketNumber { return h.packetNumber }
func (h *LongHeader) TruncatedPN() TruncatedPN { return h.truncatedPN }
func (h *LongHeader) EncryptionLevel() EncryptionLevel { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *LongHeader) HeaderLength() int {
	length := 7 + len(h.DestinationCID) + len(h.SourceCID) + h.Length.Length + h.truncatedPN.Length
	if h.packetType == Initial {
		length += h.TokenLength.Length + len(h.Token)
	}
	return length
}
func ReadLongHeader(buffer *bytes.Reader, conn *Connection) *LongHeader {
	h := new(LongHeader)
	typeByte, _ := buffer.ReadByte()
	h.lowerBits = typeByte & 0x0F
	h.packetType = PacketType(typeByte - 0xC0) >> 4
	binary.Read(buffer, binary.BigEndian, &h.Version)
	DCIL, _ := buffer.ReadByte()
	h.DestinationCID = make([]byte, DCIL, DCIL)
	binary.Read(buffer, binary.BigEndian, &h.DestinationCID)
	SCIL, _ := buffer.ReadByte()
	h.SourceCID = make([]byte, SCIL, SCIL)
	binary.Read(buffer, binary.BigEndian, &h.SourceCID)
	if h.packetType == Initial {
		h.TokenLength, _ = ReadVarInt(buffer)
		h.Token = make([]byte, h.TokenLength.Value)
		buffer.Read(h.Token)
	}
	if h.packetType != Retry {
		h.Length, _ = ReadVarInt(buffer)
		h.truncatedPN = ReadTruncatedPN(buffer, int(typeByte & 0x3) + 1)
		h.packetNumber = h.truncatedPN.Join(conn.LargestPNsReceived[h.packetType.PNSpace()])
	}
	return h
}
func NewLongHeader(packetType PacketType, conn *Connection, space PNSpace) *LongHeader {
	h := new(LongHeader)
	h.packetType = packetType
	h.Version = conn.Version
	h.SourceCID = conn.SourceCID
	if packetType == ZeroRTTProtected {
		h.DestinationCID = conn.OriginalDestinationCID
	} else {
		h.DestinationCID = conn.DestinationCID
	}
	h.TokenLength = NewVarInt(0)
	h.packetNumber = conn.nextPacketNumber(space)
	h.truncatedPN = h.packetNumber.Truncate(conn.LargestPNsAcknowledged[h.packetType.PNSpace()])
	return h
}

func (t PacketType) String() string {
	return packetTypeToString[t]
}

func (t PacketType) PNSpace() PNSpace {
	return packetTypeToPNSPace[t]
}

type ShortHeader struct {
	SpinBit 	   SpinBit
	KeyPhase       KeyPhaseBit
	DestinationCID ConnectionID
	truncatedPN    TruncatedPN
	packetNumber   PacketNumber
}
func (h *ShortHeader) Encode() []byte {
	buffer := new(bytes.Buffer)
	var typeByte uint8
	typeByte |= 0x40
	if h.SpinBit == SpinValueOne {
		typeByte |= 0x20
	}
	if h.KeyPhase == KeyPhaseOne {
		typeByte |= 0x04
	}
	typeByte |= uint8(h.truncatedPN.Length) - 1
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.DestinationCID)
	buffer.Write(h.truncatedPN.Encode())

	return buffer.Bytes()
}
func (h *ShortHeader) PacketType() PacketType                { return ShortHeaderPacket }
func (h *ShortHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *ShortHeader) PacketNumber() PacketNumber            { return h.packetNumber }
func (h *ShortHeader) TruncatedPN() TruncatedPN              { return h.truncatedPN }
func (h *ShortHeader) EncryptionLevel() EncryptionLevel      { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *ShortHeader) HeaderLength() int                     { return 1 + len(h.DestinationCID) + h.truncatedPN.Length }
func ReadShortHeader(buffer *bytes.Reader, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	typeByte, _ := buffer.ReadByte()
	h.SpinBit = (typeByte & 0x20) == 0x20
	h.KeyPhase = (typeByte & 0x04) == 0x04

	h.DestinationCID = make([]byte, len(conn.SourceCID))
	buffer.Read(h.DestinationCID)
	h.truncatedPN = ReadTruncatedPN(buffer, int(typeByte&0x3) + 1)
	h.packetNumber = h.truncatedPN.Join(conn.LargestPNsReceived[PNSpaceAppData])
	return h
}
func NewShortHeader(conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.SpinBit = conn.SpinBit
	h.KeyPhase = conn.KeyPhaseIndex % 2 == 1
	h.DestinationCID = conn.DestinationCID
	h.packetNumber = conn.nextPacketNumber(PNSpaceAppData)
	h.truncatedPN = h.packetNumber.Truncate(conn.LargestPNsAcknowledged[PNSpaceAppData])
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true

type SpinBit bool
const SpinValueZero SpinBit = false
const SpinValueOne SpinBit = true
