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
	"errors"
	"time"
)

type Frame interface {
	FrameType() FrameType
	writeTo(buffer *bytes.Buffer)
	shouldBeRetransmitted() bool
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
	case frameType == PathChallengeType:
		return Frame(ReadPathChallenge(buffer)), nil
	case frameType == PathResponseType:
		return Frame(ReadPathResponse(buffer)), nil
	case (frameType & StreamType) == StreamType && frameType <= 0x17:
		return Frame(ReadStreamFrame(buffer, conn)), nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown frame type %d", typeByte))
	}
}
type FrameType uint8

const (
	PaddingFrameType     FrameType = 0x00
	ResetStreamType      FrameType = 0x01
	ConnectionCloseType  FrameType = 0x02
	ApplicationCloseType FrameType = 0x03
	MaxDataType          FrameType = 0x04
	MaxStreamDataType    FrameType = 0x05
	MaxStreamIdType      FrameType = 0x06
	PingType             FrameType = 0x07
	BlockedType          FrameType = 0x08
	StreamBlockedType    FrameType = 0x09
	StreamIdBlockedType  FrameType = 0x0a
	NewConnectionIdType  FrameType = 0x0b
	StopSendingType      FrameType = 0x0c
	AckType              FrameType = 0x0d
	PathChallengeType    FrameType = 0x0e
	PathResponseType     FrameType = 0x0f
	StreamType           FrameType = 0x10
)

type PaddingFrame byte

func (frame PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (frame PaddingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func (frame PaddingFrame) shouldBeRetransmitted() bool { return false }
func NewPaddingFrame(buffer *bytes.Reader) *PaddingFrame {
	buffer.ReadByte()  // Discard frame payload
	return new(PaddingFrame)
}

type ResetStream struct {
	StreamId    uint64
	ErrorCode   uint16
	FinalOffset uint64
}
func (frame ResetStream) FrameType() FrameType { return ResetStreamType }
func (frame ResetStream) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.StreamId)
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
	WriteVarInt(buffer, frame.FinalOffset)
}
func (frame ResetStream) shouldBeRetransmitted() bool { return true }
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	frame.FinalOffset, _ = ReadVarInt(buffer)
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
func (frame ConnectionCloseFrame) shouldBeRetransmitted() bool { return false }
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
func (frame ApplicationCloseFrame) shouldBeRetransmitted() bool { return false }
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
func (frame MaxDataFrame) shouldBeRetransmitted() bool { return true }
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
func (frame MaxStreamDataFrame) shouldBeRetransmitted() bool { return true }
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
func (frame MaxStreamIdFrame) shouldBeRetransmitted() bool { return true }
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.maximumStreamId, _ = ReadVarInt(buffer)
	return frame
}


type PingFrame byte
func (frame PingFrame) FrameType() FrameType { return PingType }
func (frame PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func (frame PingFrame) shouldBeRetransmitted() bool { return true }
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	frame := new(PingFrame)
	buffer.ReadByte()  // Discard frame type
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
func (frame BlockedFrame) shouldBeRetransmitted() bool { return true }
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
func (frame StreamBlockedFrame) shouldBeRetransmitted() bool { return true }
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
func (frame StreamIdBlockedFrame) shouldBeRetransmitted() bool { return true }
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdBlockedFrame {
	frame := new(StreamIdBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarInt(buffer)
	return frame
}

type NewConnectionIdFrame struct {
	Sequence            uint64
	Length 			    uint8
	ConnectionId        []byte
	StatelessResetToken [16]byte
}
func (frame NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.Sequence)
	buffer.WriteByte(frame.Length)
	buffer.Write(frame.ConnectionId)
	binary.Write(buffer, binary.BigEndian, frame.StatelessResetToken)
}
func (frame NewConnectionIdFrame) shouldBeRetransmitted() bool { return true }
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.Sequence, _ = ReadVarInt(buffer)
	frame.Length, _ = buffer.ReadByte()
	frame.ConnectionId = make([]byte, frame.Length, frame.Length)
	buffer.Read(frame.ConnectionId)
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
func (frame StopSendingFrame) shouldBeRetransmitted() bool { return true }
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarInt(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	return frame
}

type AckFrame struct {
	LargestAcknowledged uint64
	AckDelay            uint64
	AckBlockCount       uint64
	AckBlocks           []AckBlock
}
type AckBlock struct {
	gap uint64
	block uint64
}
func (frame AckFrame) FrameType() FrameType { return AckType }
func (frame AckFrame) shouldBeRetransmitted() bool { return false }
func (frame AckFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	WriteVarInt(buffer, frame.LargestAcknowledged)
	WriteVarInt(buffer, frame.AckDelay)
	WriteVarInt(buffer, frame.AckBlockCount)
	for i, ack := range frame.AckBlocks {
		if i > 0 {
			WriteVarInt(buffer, ack.gap)
		}
		WriteVarInt(buffer, ack.block)
	}
}
func (frame AckFrame) GetAckedPackets() []uint64 {
	var packets []uint64

	currentPacketNumber := frame.LargestAcknowledged
	packets = append(packets, currentPacketNumber)
	for i := uint64(0); i < frame.AckBlocks[0].block; i++ {
		currentPacketNumber--
		packets = append(packets, currentPacketNumber)
	}
	for _, ackBlock := range frame.AckBlocks[1:] {
		for i := uint64(0); i <= ackBlock.gap; i++ {  // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.block; i++ {
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
	}
	return packets
}
func ReadAckFrame(buffer *bytes.Reader) *AckFrame {
	frame := new(AckFrame)
	buffer.ReadByte()  // Discard frame byte

	frame.LargestAcknowledged, _ = ReadVarInt(buffer)
	frame.AckDelay, _ = ReadVarInt(buffer)
	frame.AckBlockCount, _ = ReadVarInt(buffer)

	firstBlock := AckBlock{}
	firstBlock.block, _ = ReadVarInt(buffer)
	frame.AckBlocks = append(frame.AckBlocks, firstBlock)

	var i uint64
	for i = 0; i < frame.AckBlockCount; i++ {
		ack := AckBlock{}
		ack.gap, _ = ReadVarInt(buffer)
		ack.block, _ = ReadVarInt(buffer)
		frame.AckBlocks = append(frame.AckBlocks, ack)
	}
	return frame
}
func NewAckFrame(largestAcknowledged uint64, ackBlockCount uint64) *AckFrame {
	frame := new(AckFrame)
	frame.LargestAcknowledged = largestAcknowledged
	frame.AckBlockCount = 0
	frame.AckDelay = 0
	frame.AckBlocks = append(frame.AckBlocks, AckBlock{0, ackBlockCount})
	return frame
}

type PathChallenge struct {
	Data [8]byte
}
func (frame PathChallenge) FrameType() FrameType { return PathChallengeType }
func (frame PathChallenge) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	buffer.Write(frame.Data[:])
}
func (frame PathChallenge) shouldBeRetransmitted() bool { return true }
func ReadPathChallenge(buffer *bytes.Reader) *PathChallenge {
	frame := new(PathChallenge)
	buffer.ReadByte()  // Discard frame byte
	buffer.Read(frame.Data[:])
	return frame
}

type PathResponse struct {
	Data [8]byte
}
func (frame PathResponse) FrameType() FrameType { return PathResponseType }
func (frame PathResponse) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	buffer.Write(frame.Data[:])
}
func (frame PathResponse) shouldBeRetransmitted() bool { return false }
func ReadPathResponse(buffer *bytes.Reader) *PathResponse {
	frame := new(PathResponse)
	buffer.ReadByte()  // Discard frame byte
	buffer.Read(frame.Data[:])
	return frame
}
func NewPathResponse(data [8]byte) *PathResponse {
	frame := new(PathResponse)
	frame.Data = data
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
func (frame StreamFrame) shouldBeRetransmitted() bool { return true }
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
		stream = &Stream{}
		conn.Streams[frame.StreamId] = stream
	}

	conn.Streams.Get(frame.StreamId).addToRead(frame)

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

type RetransmitBatch []RetransmittableFrames

type RetransmittableFrames struct {
	Frames    []Frame
	Timestamp time.Time
	IsInitial bool
}
func NewRetransmittableFrames(frames []Frame) *RetransmittableFrames {
	r := new(RetransmittableFrames)
	r.Frames = frames
	r.Timestamp = time.Now()
	return r
}
func (a RetransmitBatch) Less(i, j int) bool { return a[i].Timestamp.Before(a[j].Timestamp) }
func (a RetransmitBatch) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a RetransmitBatch) Len() int           { return len(a) }