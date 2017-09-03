package main

import (
	"bytes"
	"encoding/binary"
)

type Header interface {
	PacketNumber() uint32
	encode() []byte
}
func ReadHeader(buffer *bytes.Reader) Header {
	var h Header
	typeByte, _ := buffer.ReadByte()
	buffer.UnreadByte()
	if typeByte & 0x80 == 0x80 {
		h = ReadLongHeader(buffer)
	} else {
		h = ReadShortHeader(buffer)
	}
	return h
}

type LongHeader struct {
	packetType   LongPacketType
	connectionId uint64
	packetNumber uint32
	version      uint32
}
func (h LongHeader) encode() []byte {
	buffer := new(bytes.Buffer)
	typeByte := uint8(0x80)
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.connectionId)
	binary.Write(buffer, binary.BigEndian, h.packetNumber)
	binary.Write(buffer, binary.BigEndian, h.version)
	return buffer.Bytes()
}
func (h LongHeader) PacketNumber() uint32 {
	return h.packetNumber
}
func ReadLongHeader(buffer *bytes.Reader) *LongHeader {
	h := new(LongHeader)
	typeByte, _ := buffer.ReadByte()
	h.packetType = LongPacketType(typeByte - 0x80)
	binary.Read(buffer, binary.BigEndian, &h.connectionId)
	binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	binary.Read(buffer, binary.BigEndian, &h.version)
	return h
}
func NewLongHeader(packetType LongPacketType, conn *Connection) *LongHeader {
	h := new(LongHeader)
	h.packetType = packetType
	h.connectionId = conn.connectionId
	h.packetNumber = uint32(conn.nextPacketNumber())
	h.version = conn.version
	return h
}

type LongPacketType uint8
const VersionNegotiation	LongPacketType = 0x01
const ClientInitial			LongPacketType = 0x02
const ServerStatelessRetry	LongPacketType = 0x03
const ServerCleartext 		LongPacketType = 0x04
const ClientCleartext 		LongPacketType = 0x05
const ZeroRTTProtected 		LongPacketType = 0x06
const OneRTTProtectedKP0 	LongPacketType = 0x06
const OneRTTProtectedKP1 	LongPacketType = 0x07

type ShortHeader struct {
	connectionIdFlag 	bool
	keyPhase			KeyPhaseBit
	packetType 			ShortHeaderPacketType
	connectionId 		uint64
	packetNumber        uint32
}
func (h *ShortHeader) encode() []byte {
	buffer := new(bytes.Buffer)
	var typeByte uint8
	if h.connectionIdFlag {
		typeByte |= 0x40
	}
	if h.keyPhase == KeyPhaseOne {
		typeByte |= 0x20
	}
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.connectionId)
	switch h.packetType {
	case OneBytePacketNumber:
		binary.Write(buffer, binary.BigEndian, uint8(h.packetNumber))
	case TwoBytesPacketNumber:
		binary.Write(buffer, binary.BigEndian, uint16(h.packetNumber))
	case FourBytesPacketNumber:
		binary.Write(buffer, binary.BigEndian, h.packetNumber)
	}
	return buffer.Bytes()
}
func (h *ShortHeader) PacketNumber() uint32 {
	return h.packetNumber
}
func ReadShortHeader(buffer *bytes.Reader) *ShortHeader {
	h := new(ShortHeader)
	typeByte, _ := buffer.ReadByte()
	h.connectionIdFlag = (typeByte & 0x40) == 0x40
	h.keyPhase = (typeByte & 0x20) == 0x20
	h.packetType = ShortHeaderPacketType(typeByte & 0x1F)
	if h.connectionIdFlag {
		binary.Read(buffer, binary.BigEndian, h.connectionId)
	}
	switch h.packetType {
	case OneBytePacketNumber:
		var number uint8
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = uint32(number)
	case TwoBytesPacketNumber:
		var number uint16
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = uint32(number)
	case FourBytesPacketNumber:
		binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	}
	return h
}
func NewShortHeader(packetType ShortHeaderPacketType, keyPhase KeyPhaseBit, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.connectionIdFlag = !conn.omitConnectionId
	h.keyPhase = keyPhase
	h.packetType = packetType
	h.connectionId = conn.connectionId
	h.packetNumber = uint32(conn.nextPacketNumber())
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true

type ShortHeaderPacketType uint8
const OneBytePacketNumber ShortHeaderPacketType = 0x01
const TwoBytesPacketNumber ShortHeaderPacketType = 0x02
const FourBytesPacketNumber ShortHeaderPacketType = 0x03