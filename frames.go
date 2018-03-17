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
	"io"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"errors"
)

type Frame interface {
	FrameType() FrameType
	writeTo(buffer *bytes.Buffer)
}
func NewFrame(buffer *bytes.Reader, conn *Connection) (Frame, error) {
	typeByte, err := buffer.ReadByte()
	if err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	buffer.UnreadByte()
	frameType := FrameType(typeByte)
	switch {
	case frameType == PaddingFrameType:
		return Frame(NewPaddingFrame(buffer)), nil
	case frameType == ResetStreamType:
		return Frame(NewResetStream(buffer)), nil
	case frameType == ConnectionCloseType:
		return Frame(NewConnectionCloseFrame(buffer)), nil
	case frameType == ApplicationCloseType:
		return Frame(NewApplicationCloseFrame(buffer)), nil
	case frameType == MaxDataType:
		return Frame(NewMaxDataFrame(buffer)), nil
	case frameType == MaxStreamDataType:
		return Frame(NewMaxStreamDataFrame(buffer)), nil
	case frameType == MaxStreamIdType:
		return Frame(NewMaxStreamIdFrame(buffer)), nil
	case frameType == PingType:
		return Frame(NewPingFrame(buffer)), nil
	case frameType == BlockedType:
		return Frame(NewBlockedFrame(buffer)), nil
	case frameType == StreamBlockedType:
		return Frame(NewStreamBlockedFrame(buffer)), nil
	case frameType == StreamIdBlockedType:
		return Frame(NewStreamIdNeededFrame(buffer)), nil
	case frameType == NewConnectionIdType:
		return Frame(NewNewConnectionIdFrame(buffer)), nil
	case frameType == StopSendingType:
		return Frame(NewStopSendingFrame(buffer)), nil
	case frameType == AckType:
		return Frame(ReadAckFrame(buffer)), nil
	case (frameType & StreamType) == StreamType && frameType <= 0x17:
		return Frame(ReadStreamFrame(buffer, conn)), nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown frame type %d", typeByte))
	}
}
type FrameType uint8

const PaddingFrameType FrameType = 0x00
const ResetStreamType FrameType = 0x01
const ConnectionCloseType FrameType = 0x02
const ApplicationCloseType FrameType = 0x03
const MaxDataType FrameType = 0x04
const MaxStreamDataType FrameType = 0x05
const MaxStreamIdType FrameType = 0x06
const PingType FrameType = 0x07
const BlockedType FrameType = 0x08
const StreamBlockedType FrameType = 0x09
const StreamIdBlockedType FrameType = 0x0a
const NewConnectionIdType FrameType = 0x0b
const StopSendingType FrameType = 0x0c
const PongType FrameType = 0x0d
const AckType FrameType = 0x0e
const StreamType FrameType = 0x10

type PaddingFrame byte

func (frame PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (frame PaddingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewPaddingFrame(buffer *bytes.Reader) *PaddingFrame {
	buffer.ReadByte()  // Discard frame payload
	return new(PaddingFrame)
}

type ResetStream struct {
	streamId    uint64
	errorCode   uint16
	finalOffset uint64
}
func (frame ResetStream) FrameType() FrameType { return ResetStreamType }
func (frame ResetStream) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	WriteVarInt(buffer, frame.finalOffset)
}
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	frame.finalOffset, _ = ReadVarInt(buffer)
	return frame
}

type ConnectionCloseFrame struct {
	ErrorCode          uint16
	ReasonPhraseLength uint64
	ReasonPhrase       string
}
func (frame ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (frame ConnectionCloseFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
	WriteVarInt(buffer, frame.ReasonPhraseLength)
	if frame.ReasonPhraseLength > 0 {
		buffer.Write([]byte(frame.ReasonPhrase))
	}
}
func NewConnectionCloseFrame(buffer *bytes.Reader) *ConnectionCloseFrame {
	frame := new(ConnectionCloseFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	frame.ReasonPhraseLength, _ = ReadVarInt(buffer)
	if frame.ReasonPhraseLength > 0 {
		reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.ReasonPhrase = string(reasonBytes)
	}
	return frame
}

type ApplicationCloseFrame struct {
	errorCode          uint16
	reasonPhraseLength uint64
	reasonPhrase       string
}
func (frame ApplicationCloseFrame) FrameType() FrameType { return ApplicationCloseType }
func (frame ApplicationCloseFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	WriteVarInt(buffer, frame.reasonPhraseLength)
	if frame.reasonPhraseLength > 0 {
		buffer.Write([]byte(frame.reasonPhrase))
	}
}
func NewApplicationCloseFrame(buffer *bytes.Reader) *ApplicationCloseFrame {
	frame := new(ApplicationCloseFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	frame.reasonPhraseLength, _ = ReadVarInt(buffer)
	if frame.reasonPhraseLength > 0 {
		reasonBytes := make([]byte, frame.reasonPhraseLength, frame.reasonPhraseLength)
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.reasonPhrase = string(reasonBytes)
	}
	return frame
}


type MaxDataFrame struct {
	MaximumData uint64
}
func (frame MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (frame MaxDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.MaximumData)
}
func NewMaxDataFrame(buffer *bytes.Reader) *MaxDataFrame {
	frame := new(MaxDataFrame)
	buffer.ReadByte()  // Discard frame type
	frame.MaximumData, _ = ReadVarInt(buffer)
	return frame
}

type MaxStreamDataFrame struct {
	StreamId          uint64
	MaximumStreamData uint64
}
func (frame MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (frame MaxStreamDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.MaximumStreamData)
}
func NewMaxStreamDataFrame(buffer *bytes.Reader) *MaxStreamDataFrame {
	frame := new(MaxStreamDataFrame)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarInt(buffer)
	frame.MaximumStreamData, _ = ReadVarInt(buffer)
	return frame
}

type MaxStreamIdFrame struct {
	maximumStreamId uint64
}
func (frame MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (frame MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.maximumStreamId)
}
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.maximumStreamId, _ = ReadVarInt(buffer)
	return frame
}


type PingFrame struct {
	length uint8
	data []byte
}
func (frame PingFrame) FrameType() FrameType { return PingType }
func (frame PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	buffer.WriteByte(frame.length)
	if frame.length > 0 {
		buffer.Write(frame.data)
	}
}
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	frame := new(PingFrame)
	buffer.ReadByte()  // Discard frame type
	frame.length, _ = buffer.ReadByte()
	if frame.length > 0 {
		frame.data = make([]byte, frame.length, frame.length)
		buffer.Read(frame.data)
	}
	return frame
}

type BlockedFrame struct {
	offset uint64
}
func (frame BlockedFrame) FrameType() FrameType { return BlockedType }
func (frame BlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.offset)
}
func NewBlockedFrame(buffer *bytes.Reader) *BlockedFrame {
	frame := new(BlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.offset, _ = ReadVarInt(buffer)
	return frame
}

type StreamBlockedFrame struct {
	streamId uint64
	offset   uint64
}
func (frame StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (frame StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.streamId)
	WriteVarInt(buffer, frame.offset)
}
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamBlockedFrame {
	frame := new(StreamBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarInt(buffer)
	frame.offset, _ = ReadVarInt(buffer)
	return frame
}

type StreamIdBlockedFrame struct {
	streamId uint64
}
func (frame StreamIdBlockedFrame) FrameType() FrameType { return StreamIdBlockedType }
func (frame StreamIdBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.streamId)
}
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdBlockedFrame {
	frame := new(StreamIdBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarInt(buffer)
	return frame
}

type NewConnectionIdFrame struct {
	Sequence            uint64
	ConnectionId        uint64
	StatelessResetToken [16]byte
}
func (frame NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.Sequence)
	WriteVarInt(buffer, frame.ConnectionId)
	binary.Write(buffer, binary.BigEndian, frame.StatelessResetToken)
}
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.Sequence, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ConnectionId)
	binary.Read(buffer, binary.BigEndian, &frame.StatelessResetToken)
	return frame
}

type StopSendingFrame struct {
	StreamId  uint64
	ErrorCode uint16
}
func (frame StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (frame StopSendingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.StreamId)
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
}
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	return frame
}

type PongFrame struct {
	PingFrame
}

func (frame PongFrame) FrameType() FrameType { return PongType }

func NewPongFrame(buffer *bytes.Reader) *PongFrame {
	frame := new(PongFrame)
	buffer.ReadByte()  // Discard frame type
	frame.length, _ = buffer.ReadByte()
	if frame.length > 0 {
		frame.data = make([]byte, frame.length, frame.length)
		buffer.Read(frame.data)
	}
	return frame
}

type AckFrame struct {
	LargestAcknowledged uint64
	ackDelay            uint64
	ackBlockCount       uint64
	ackBlocks           []AckBlock
}
type AckBlock struct {
	gap uint64
	block uint64
}
func (frame AckFrame) FrameType() FrameType { return AckType }
func (frame AckFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.LargestAcknowledged)
	WriteVarInt(buffer, frame.ackDelay)
	WriteVarInt(buffer, frame.ackBlockCount)
	for i, ack := range frame.ackBlocks {
		if i > 0 {
			WriteVarInt(buffer, ack.gap)
		}
		WriteVarInt(buffer, ack.block)
	}
}
func ReadAckFrame(buffer *bytes.Reader) *AckFrame {
	frame := new(AckFrame)
	buffer.ReadByte()  // Discard frame byte

	frame.LargestAcknowledged, _ = ReadVarInt(buffer)
	frame.ackDelay, _ = ReadVarInt(buffer)
	frame.ackBlockCount, _ = ReadVarInt(buffer)

	firstBlock := AckBlock{}
	firstBlock.block, _ = ReadVarInt(buffer)
	frame.ackBlocks = append(frame.ackBlocks, firstBlock)

	var i uint64
	for i = 0; i < frame.ackBlockCount; i++ {
		ack := AckBlock{}
		ack.gap, _ = ReadVarInt(buffer)
		ack.block, _ = ReadVarInt(buffer)
		frame.ackBlocks = append(frame.ackBlocks, ack)
	}
	return frame
}
func NewAckFrame(largestAcknowledged uint64, ackBlockCount uint64) *AckFrame {
	frame := new(AckFrame)
	frame.LargestAcknowledged = largestAcknowledged
	frame.ackBlockCount = 0
	frame.ackDelay = 0
	frame.ackBlocks = append(frame.ackBlocks, AckBlock{0, ackBlockCount})
	return frame
}

type StreamFrame struct {
	FinBit bool
	LenBit bool
	OffBit bool

	StreamId   uint64
	Offset     uint64
	Length     uint64
	StreamData []byte
}
func (frame StreamFrame) FrameType() FrameType { return StreamType }
func (frame StreamFrame) writeTo(buffer *bytes.Buffer) {
	typeByte := byte(frame.FrameType())
	if frame.FinBit {
		typeByte |= 0x01
	}
	if frame.LenBit {
		typeByte |= 0x02
	}
	if frame.OffBit {
		typeByte |= 0x04
	}
	binary.Write(buffer, binary.BigEndian, typeByte)
	WriteVarInt(buffer, frame.StreamId)
	if frame.OffBit {
		WriteVarInt(buffer, frame.Offset)
	}
	if frame.LenBit {
		WriteVarInt(buffer, frame.Length)
	}
	buffer.Write(frame.StreamData)
}
func ReadStreamFrame(buffer *bytes.Reader, conn *Connection) *StreamFrame {
	frame := new(StreamFrame)
	typeByte, _ := buffer.ReadByte()
	frame.FinBit = (typeByte & 0x01) == 0x01
	frame.LenBit = (typeByte & 0x02) == 0x02
	frame.OffBit = (typeByte & 0x04) == 0x04

	frame.StreamId, _ = ReadVarInt(buffer)
	if frame.OffBit {
		frame.Offset, _ = ReadVarInt(buffer)
	}
	if frame.LenBit {
		frame.Length, _ = ReadVarInt(buffer)
	} else {
		frame.Length = uint64(buffer.Len())
	}
	frame.StreamData = make([]byte, frame.Length, frame.Length)
	buffer.Read(frame.StreamData)

	stream, ok := conn.Streams[frame.StreamId]
	if !ok {
		spew.Dump(frame)
		panic(frame)
	}
	if frame.Offset == stream.ReadOffset {
		stream.ReadOffset += uint64(frame.Length)
		stream.ReadData = append(stream.ReadData, frame.StreamData...)
		if frame.FinBit {
			stream.ReadClosed = frame.FinBit
		}
	}

	return frame
}
func NewStreamFrame(streamId uint64, stream *Stream, data []byte, finBit bool) *StreamFrame {
	frame := new(StreamFrame)
	frame.StreamId = streamId
	frame.FinBit = finBit
	frame.LenBit = true
	frame.Offset = stream.WriteOffset
	frame.OffBit = frame.Offset > 0
	frame.Length = uint64(len(data))
	frame.StreamData = data
	stream.WriteOffset += uint64(frame.Length)
	stream.WriteData = append(stream.WriteData, data...)
	stream.WriteClosed = frame.FinBit
	return frame
}
