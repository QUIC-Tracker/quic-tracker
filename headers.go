package quictracker

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type Header interface {
	PacketType() PacketType
	DestinationConnectionID() ConnectionID
	PacketNumber() PacketNumber
	TruncatedPN() TruncatedPN
	EncryptionLevel() EncryptionLevel
	Encode() []byte
	Length() int
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
	Version        uint32
	DestinationCID ConnectionID
	SourceCID      ConnectionID
	PayloadLength  VarInt
	TokenLength    VarInt
	Token		   []byte
	packetNumber   PacketNumber
	truncatedPN    TruncatedPN
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
		buffer.Write(h.TokenLength.Encode())
		buffer.Write(h.Token)
	}
	buffer.Write(h.PayloadLength.Encode())
	buffer.Write(h.truncatedPN.Encode())
	return buffer.Bytes()
}
func (h *LongHeader) PacketType() PacketType { return h.packetType }
func (h *LongHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *LongHeader) PacketNumber() PacketNumber { return h.packetNumber }
func (h *LongHeader) TruncatedPN() TruncatedPN { return h.truncatedPN }
func (h *LongHeader) EncryptionLevel() EncryptionLevel { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *LongHeader) Length() int {
	length := 6 + len(h.DestinationCID) + len(h.SourceCID) + h.PayloadLength.Length + h.truncatedPN.Length
	if h.packetType == Initial {
		length += h.TokenLength.Length + len(h.Token)
	}
	return length
}
func ReadLongHeader(buffer *bytes.Reader, conn *Connection) *LongHeader {
	h := new(LongHeader)
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
		h.TokenLength, _ = ReadVarInt(buffer)
		h.Token = make([]byte, h.TokenLength.Value)
		buffer.Read(h.Token)
	}
	h.PayloadLength, _ = ReadVarInt(buffer)
	h.truncatedPN = ReadTruncatedPN(buffer)
	h.packetNumber = h.truncatedPN.Join(conn.LargestPNsReceived[h.packetType.PNSpace()])
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

var packetTypeToPNSPace = map[PacketType]PNSpace {
	Initial: PNSpaceInitial,
	Retry: PNSpaceNoSpace,
	Handshake: PNSpaceHandshake,
	ZeroRTTProtected: PNSpaceAppData,

	ShortHeaderPacket: PNSpaceAppData,
}

func (t PacketType) String() string {
	return packetTypeToString[t]
}

func (t PacketType) PNSpace() PNSpace {
	return packetTypeToPNSPace[t]
}

type ShortHeader struct {
	KeyPhase       KeyPhaseBit
	DestinationCID ConnectionID
	truncatedPN    TruncatedPN
	packetNumber   PacketNumber
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
	buffer.Write(h.truncatedPN.Encode())

	return buffer.Bytes()
}
func (h *ShortHeader) PacketType() PacketType { return ShortHeaderPacket }
func (h *ShortHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *ShortHeader) PacketNumber() PacketNumber { return h.packetNumber }
func (h *ShortHeader) TruncatedPN() TruncatedPN { return h.truncatedPN }
func (h *ShortHeader) EncryptionLevel() EncryptionLevel { return packetTypeToEncryptionLevel[h.PacketType()] }
func (h *ShortHeader) Length() int { return 1 + len(h.DestinationCID) + h.truncatedPN.Length }
func ReadShortHeader(buffer *bytes.Reader, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	typeByte, _ := buffer.ReadByte()
	h.KeyPhase = (typeByte & 0x40) == 0x40

	if typeByte & 0x38 != 0x30 {
		fmt.Printf("SH fixed bits not respected: expected %b, got %b\n", 0x30, typeByte & 0x38)
	}

	h.DestinationCID = make([]byte, len(conn.SourceCID))
	buffer.Read(h.DestinationCID)
	h.truncatedPN = ReadTruncatedPN(buffer)
	h.packetNumber = h.truncatedPN.Join(conn.LargestPNsReceived[PNSpaceAppData])
	return h
}
func NewShortHeader(keyPhase KeyPhaseBit, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.KeyPhase = keyPhase
	h.DestinationCID = conn.DestinationCID
	h.packetNumber = conn.nextPacketNumber(PNSpaceAppData)
	h.truncatedPN = h.packetNumber.Truncate(conn.LargestPNsAcknowledged[PNSpaceAppData])
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true
