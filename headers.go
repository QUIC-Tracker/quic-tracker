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
)

type Header interface {
	PacketNumber() uint32
	PacketType() PacketType
	ConnectionId() uint64
	encode() []byte
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
	packetType   PacketType
	connectionId uint64
	Version      uint32
	packetNumber uint32
}
func (h LongHeader) encode() []byte {
	buffer := new(bytes.Buffer)
	typeByte := uint8(0x80)
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	binary.Write(buffer, binary.BigEndian, h.connectionId)
	binary.Write(buffer, binary.BigEndian, h.Version)
	binary.Write(buffer, binary.BigEndian, h.packetNumber)
	return buffer.Bytes()
}
func (h LongHeader) PacketNumber() uint32 {
	return h.packetNumber
}
func (h LongHeader) PacketType() PacketType {
	return h.packetType
}
func (h LongHeader) ConnectionId() uint64 {
	return h.connectionId
}
func ReadLongHeader(buffer *bytes.Reader) *LongHeader {
	h := new(LongHeader)
	typeByte, _ := buffer.ReadByte()
	h.packetType = PacketType(typeByte - 0x80)
	binary.Read(buffer, binary.BigEndian, &h.connectionId)
	binary.Read(buffer, binary.BigEndian, &h.Version)
	binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	return h
}
func NewLongHeader(packetType PacketType, conn *Connection) *LongHeader {
	h := new(LongHeader)
	h.packetType = packetType
	h.connectionId = conn.ConnectionId
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

	OneBytePacketNumber   PacketType = 0x1f
	TwoBytesPacketNumber  PacketType = 0x1e
	FourBytesPacketNumber PacketType = 0x1d
)

type ShortHeader struct {
	omitConnectionIdFlag bool
	keyPhase             KeyPhaseBit
	packetType           PacketType
	connectionId         uint64
	packetNumber         uint32
}
func (h ShortHeader) encode() []byte {
	buffer := new(bytes.Buffer)
	var typeByte uint8
	if h.omitConnectionIdFlag {
		typeByte |= 0x40
	}
	if h.keyPhase == KeyPhaseOne {
		typeByte |= 0x20
	}
	typeByte |= uint8(h.packetType)
	binary.Write(buffer, binary.BigEndian, typeByte)
	if !h.omitConnectionIdFlag {
		binary.Write(buffer, binary.BigEndian, h.connectionId)
	}
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
func (h ShortHeader) PacketNumber() uint32 {
	return h.packetNumber
}
func (h ShortHeader) PacketType() PacketType {
	return h.packetType
}
func (h ShortHeader) ConnectionId() uint64 {
	return h.connectionId
}
func ReadShortHeader(buffer *bytes.Reader, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	typeByte, _ := buffer.ReadByte()
	h.omitConnectionIdFlag = (typeByte & 0x40) == 0x40
	h.keyPhase = (typeByte & 0x20) == 0x20
	h.packetType = PacketType(typeByte & 0x1F)
	if !h.omitConnectionIdFlag {
		binary.Read(buffer, binary.BigEndian, &h.connectionId)
	}
	switch h.packetType {
	case OneBytePacketNumber:
		var number uint8
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = (uint32(conn.expectedPacketNumber) & 0xffffff00) | uint32(number)
	case TwoBytesPacketNumber:
		var number uint16
		binary.Read(buffer, binary.BigEndian, &number)
		h.packetNumber = (uint32(conn.expectedPacketNumber) & 0xffff0000) | uint32(number)
	case FourBytesPacketNumber:
		binary.Read(buffer, binary.BigEndian, &h.packetNumber)
	}
	return h
}
func NewShortHeader(packetType PacketType, keyPhase KeyPhaseBit, conn *Connection) *ShortHeader {
	h := new(ShortHeader)
	h.omitConnectionIdFlag = conn.omitConnectionId
	h.keyPhase = keyPhase
	h.packetType = packetType
	h.connectionId = conn.ConnectionId
	h.packetNumber = uint32(conn.nextPacketNumber())
	return h
}

type KeyPhaseBit bool
const KeyPhaseZero KeyPhaseBit = false
const KeyPhaseOne KeyPhaseBit = true
