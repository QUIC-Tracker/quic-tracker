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
	"math"
)

type Header interface {
	PacketType() PacketType
	DestinationConnectionID() ConnectionID
	PacketNumber() uint32
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
	packetNumber   uint32
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
	WriteVarInt(buffer, h.PayloadLength)
	binary.Write(buffer, binary.BigEndian, h.packetNumber)
	return buffer.Bytes()
}
func (h *LongHeader) PacketType() PacketType { return h.packetType }
func (h *LongHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *LongHeader) PacketNumber() uint32 { return h.packetNumber }
func (h *LongHeader) Length() int { return 1 + 4 + 1 + len(h.DestinationCID) + len(h.SourceCID) + int(VarIntLen(h.PayloadLength)) + 4 }
func ReadLongHeader(buffer *bytes.Reader) *LongHeader {
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
	h.PayloadLength, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	return h
}
func NewLongHeader(packetType PacketType, conn *Connection) *LongHeader {
	h := new(LongHeader)
	h.packetType = packetType
	h.SourceCID = conn.SourceCID
	h.DestinationCID = conn.DestinationCID
	h.packetNumber = uint32(conn.nextPacketNumber())
	h.Version = conn.Version
	return h
}

type PacketType uint8

const (
	Initial          PacketType = 0x7f
	Retry            PacketType = 0x7e
	Handshake        PacketType = 0x7d
	ZeroRTTProtected PacketType = 0x7c

	OneBytePacketNumber   PacketType = 0x0
	TwoBytesPacketNumber  PacketType = 0x1
	FourBytesPacketNumber PacketType = 0x2
)

type ShortHeader struct {
	KeyPhase       KeyPhaseBit
	packetType     PacketType
	DestinationCID ConnectionID
	packetNumber   uint32
}
func (h *ShortHeader) Encode() []byte {
	buffer := new(bytes.Buffer)
	var typeByte uint8
	if h.KeyPhase == KeyPhaseOne {
		typeByte |= 0x40
	}
	typeByte |= 0x30
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.DestinationCID)

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
func (h *ShortHeader) PacketType() PacketType { return h.packetType }
func (h *ShortHeader) DestinationConnectionID() ConnectionID { return h.DestinationCID }
func (h *ShortHeader) PacketNumber() uint32 { return h.packetNumber }
func (h *ShortHeader) Length() int { return 1 + len(h.DestinationCID) + int(math.Pow(2, float64(h.packetType))) }
func ReadShortHeader(buffer *bytes.Reader, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	typeByte, _ := buffer.ReadByte()
	h.KeyPhase = (typeByte & 0x40) == 0x40

	if typeByte & 0x38 != 0x30 {
		println("SH fixed bits not respected")
	}

	h.packetType = PacketType(typeByte & 0x3)
	h.DestinationCID = make([]byte, len(conn.SourceCID), len(conn.SourceCID))
	buffer.Read(h.DestinationCID)

	switch h.packetType {
	case OneBytePacketNumber:
		var number uint8
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = (uint32(conn.ExpectedPacketNumber) & 0xffffff00) | uint32(number)
	case TwoBytesPacketNumber:
		var number uint16
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = (uint32(conn.ExpectedPacketNumber) & 0xffff0000) | uint32(number)
	case FourBytesPacketNumber:
		binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	}
	return h
}
func NewShortHeader(packetType PacketType, keyPhase KeyPhaseBit, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.KeyPhase = keyPhase
	h.packetType = packetType
	h.DestinationCID = conn.DestinationCID
	h.packetNumber = uint32(conn.nextPacketNumber())
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true
