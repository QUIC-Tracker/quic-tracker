package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"fmt"
	"github.com/davecgh/go-spew/spew"
)

type Frame interface {
	FrameType() FrameType
	writeTo(buffer *bytes.Buffer)
}
func NewFrame(buffer *bytes.Reader, conn *Connection) Frame {
	typeByte, err := buffer.ReadByte()
	if err == io.EOF {
		return nil
	} else if err != nil {
		panic(err)
	}
	buffer.UnreadByte()
	frameType := FrameType(typeByte)
	switch {
	case frameType == PaddingFrameType:
		return Frame(NewPaddingFrame(buffer))
	case frameType == ResetStreamType:
		return Frame(NewResetStream(buffer))
	case frameType == ConnectionCloseType:
		return Frame(NewConnectionCloseFrame(buffer))
	case frameType == MaxDataType:
		return Frame(NewMaxDataFrame(buffer))
	case frameType == MaxStreamDataType:
		return Frame(NewMaxStreamDataFrame(buffer))
	case frameType == MaxStreamIdType:
		return Frame(NewMaxStreamIdFrame(buffer))
	case frameType == PingType:
		return Frame(NewPingFrame(buffer))
	case frameType == BlockedType:
		return Frame(NewBlockedFrame(buffer))
	case frameType == StreamBlockedType:
		return Frame(NewStreamBlockedFrame(buffer))
	case frameType == StreamIdNeededType:
		return Frame(NewStreamIdNeededFrame(buffer))
	case frameType == NewConnectionIdType:
		return Frame(NewNewConnectionIdFrame(buffer))
	case frameType == StopSendingType:
		return Frame(NewStopSendingFrame(buffer))
	case (frameType & 0xE0) == AckType:
		return Frame(ReadAckFrame(buffer))
	case (frameType & StreamType) == StreamType:
		return Frame(ReadStreamFrame(buffer, conn))
	default:
		spew.Dump(buffer)
		panic(fmt.Sprintf("Unknown frame type %d", typeByte))
	}
}
type FrameType uint8

const PaddingFrameType FrameType = 0x00
const ResetStreamType FrameType = 0x01
const ConnectionCloseType FrameType = 0x02
const MaxDataType FrameType = 0x04
const MaxStreamDataType FrameType = 0x05
const MaxStreamIdType FrameType = 0x06
const PingType FrameType = 0x07
const BlockedType FrameType = 0x08
const StreamBlockedType FrameType = 0x09
const StreamIdNeededType FrameType = 0x0a
const NewConnectionIdType FrameType = 0x0b
const StopSendingType FrameType = 0x0c
const AckType FrameType = 0xa0
const StreamType FrameType = 0xc0

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
	streamId    uint32
	errorCode   uint32
	finalOffset uint64
}
func (frame ResetStream) FrameType() FrameType { return ResetStreamType }
func (frame ResetStream) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	binary.Write(buffer, binary.BigEndian, frame.finalOffset)
}
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	binary.Read(buffer, binary.BigEndian, &frame.finalOffset)
	return frame
}

type ConnectionCloseFrame struct {
	errorCode          uint32
	reasonPhraseLength uint16
	reasonPhrase       string
}
func (frame ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (frame ConnectionCloseFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	binary.Write(buffer, binary.BigEndian, frame.reasonPhraseLength)
	if frame.reasonPhraseLength > 0 {
		buffer.Write([]byte(frame.reasonPhrase))
	}
}
func NewConnectionCloseFrame(buffer *bytes.Reader) *ConnectionCloseFrame {
	frame := new(ConnectionCloseFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	binary.Read(buffer, binary.BigEndian, &frame.reasonPhraseLength)
	if frame.reasonPhraseLength > 0 {
		reasonBytes := make([]byte, frame.reasonPhraseLength, frame.reasonPhraseLength)
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.reasonPhrase = string(reasonBytes)
	}
	return frame
}


type MaxDataFrame struct {
	maximumData uint64
}
func (frame MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (frame MaxDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.maximumData)
}
func NewMaxDataFrame(buffer *bytes.Reader) *MaxDataFrame {
	frame := new(MaxDataFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.maximumData)
	return frame
}

type MaxStreamDataFrame struct {
	streamId uint32
	maximumStreamData uint64
}
func (frame MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (frame MaxStreamDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.maximumStreamData)
}
func NewMaxStreamDataFrame(buffer *bytes.Reader) *MaxStreamDataFrame {
	frame := new(MaxStreamDataFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	binary.Read(buffer, binary.BigEndian, &frame.maximumStreamData)
	return frame
}

type MaxStreamIdFrame struct {
	maximumStreamId uint32
}
func (frame MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (frame MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.maximumStreamId)
}
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.maximumStreamId)
	return frame
}


type PingFrame byte
func (frame PingFrame) FrameType() FrameType { return PingType }
func (frame PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	buffer.ReadByte()  // Discard frame type
	return new(PingFrame)
}

type BlockedFrame byte
func (frame BlockedFrame) FrameType() FrameType { return BlockedType }
func (frame BlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewBlockedFrame(buffer *bytes.Reader) *BlockedFrame {
	buffer.ReadByte()  // Discard frame type
	return new(BlockedFrame)
}

type StreamBlockedFrame struct {
	streamId uint32
}
func (frame StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (frame StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
}
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamBlockedFrame {
	frame := new(StreamBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	return frame
}

type StreamIdNeededFrame byte
func (frame StreamIdNeededFrame) FrameType() FrameType { return StreamIdNeededType }
func (frame StreamIdNeededFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdNeededFrame {
	buffer.ReadByte()  // Discard frame type
	return new(StreamIdNeededFrame)
}

type NewConnectionIdFrame struct {
	sequence            uint16
	connectionId        uint32
	statelessResetToken [8]byte
}
func (frame NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.sequence)
	binary.Write(buffer, binary.BigEndian, frame.connectionId)
	binary.Write(buffer, binary.BigEndian, frame.statelessResetToken)
}
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.sequence)
	binary.Read(buffer, binary.BigEndian, &frame.connectionId)
	binary.Read(buffer, binary.BigEndian, &frame.statelessResetToken)
	return frame
}

type StopSendingFrame struct {
	streamId  uint32
	errorCode uint32
}
func (frame StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (frame StopSendingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
}
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	return frame
}

type AckFrame struct {
	numBlocksPresent          bool
	largestAcknowledgedLength byte
	AckBlockLength            byte
	numAckBlocks              uint8
	numTimestamps             uint8
	largestAcknowledged       uint64
	ackDelay                  uint16
	ackBlocks                 []AckBlock
	timestamps                []Timestamp
}
type AckBlock struct {
	gap uint8
	ack uint64
}
type Timestamp struct {
	deltaLargestAcknowledged uint8
	timeSince                uint32
}
func (frame AckFrame) FrameType() FrameType { return AckType }
func (frame AckFrame) writeTo(buffer *bytes.Buffer) {
	typeByte := byte(frame.FrameType())
	if frame.numBlocksPresent {
		typeByte |= 0x10
	}
	typeByte |= frame.largestAcknowledgedLength << 2
	typeByte |= frame.AckBlockLength
	binary.Write(buffer, binary.BigEndian, typeByte)
	if frame.numBlocksPresent {
		binary.Write(buffer, binary.BigEndian, frame.numAckBlocks)
	}
	binary.Write(buffer, binary.BigEndian, frame.numTimestamps)
	switch frame.largestAcknowledgedLength {
	case 0:
		binary.Write(buffer, binary.BigEndian, uint8(frame.largestAcknowledged))
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(frame.largestAcknowledged))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(frame.largestAcknowledged))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint64(frame.largestAcknowledged))
	}
	binary.Write(buffer, binary.BigEndian, frame.ackDelay)
	for index, block := range frame.ackBlocks {
		if index > 0 {
			binary.Write(buffer, binary.BigEndian, block.gap)
		}
		switch frame.AckBlockLength {
		case 0:
			binary.Write(buffer, binary.BigEndian, uint8(block.ack))
		case 1:
			binary.Write(buffer, binary.BigEndian, uint16(block.ack))
		case 2:
			binary.Write(buffer, binary.BigEndian, uint32(block.ack))
		case 3:
			binary.Write(buffer, binary.BigEndian, uint64(block.ack))
		}
	}
	for index, timestamp := range frame.timestamps {
		binary.Write(buffer, binary.BigEndian, timestamp.deltaLargestAcknowledged)
		if index > 0 {
			binary.Write(buffer, binary.BigEndian, uint16(timestamp.timeSince))
		} else {
			binary.Write(buffer, binary.BigEndian, timestamp.timeSince)
		}
	}
}
func ReadAckFrame(buffer *bytes.Reader) *AckFrame {
	frame := new(AckFrame)
	typeByte, _ := buffer.ReadByte()
	frame.numBlocksPresent = typeByte & 0x10 == 0x10
	frame.largestAcknowledgedLength = (typeByte & 0xC) >> 2
	frame.AckBlockLength = typeByte & 0x3
	if frame.numBlocksPresent {
		binary.Read(buffer, binary.BigEndian, &frame.numAckBlocks)
	}
	binary.Read(buffer, binary.BigEndian, &frame.numTimestamps)
	switch frame.largestAcknowledgedLength {
	case 0:
		var la uint8
		binary.Read(buffer, binary.BigEndian, &la)
		frame.largestAcknowledged = uint64(la)
	case 1:
		var la uint16
		binary.Read(buffer, binary.BigEndian, &la)
		frame.largestAcknowledged = uint64(la)
	case 2:
		var la uint32
		binary.Read(buffer, binary.BigEndian, &la)
		frame.largestAcknowledged = uint64(la)
	case 3:
		binary.Read(buffer, binary.BigEndian, &frame.largestAcknowledged)
	}
	binary.Read(buffer, binary.BigEndian, &frame.ackDelay)
	for i := 0; i < int(frame.numAckBlocks) + 1; i++ {  // First ACK Block Length is always present, see https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-8.13.1
		ack := AckBlock{}
		if i > 0 {
			ack.gap, _ = buffer.ReadByte()
		}
		switch frame.AckBlockLength {
		case 0:
			var value uint8
			binary.Read(buffer, binary.BigEndian, &value)
			ack.ack = uint64(value)
		case 1:
			var value uint16
			binary.Read(buffer, binary.BigEndian, &value)
			ack.ack = uint64(value)
		case 2:
			var value uint32
			binary.Read(buffer, binary.BigEndian, &value)
			ack.ack = uint64(value)
		case 3:
			binary.Read(buffer, binary.BigEndian, &ack.ack)
		}
		frame.ackBlocks = append(frame.ackBlocks, ack)
	}
	for i:= 0; i < int(frame.numTimestamps); i++ {
		timestamp := Timestamp{}
		binary.Read(buffer, binary.BigEndian, &timestamp.deltaLargestAcknowledged)
		if i > 0 {
			var timeSince uint16
			binary.Read(buffer, binary.BigEndian, &timeSince)
			timestamp.timeSince = uint32(timeSince)
		} else {
			binary.Read(buffer, binary.BigEndian, &timestamp.timeSince)
		}
		frame.timestamps = append(frame.timestamps, timestamp)
	}
	return frame
}
func NewAckFrame(largestAcknowledged uint64, ackBlockLength uint64) *AckFrame {
	frame := new(AckFrame)
	frame.numBlocksPresent = false
	frame.largestAcknowledgedLength = 0x02
	frame.AckBlockLength = 0x02
	frame.numTimestamps = 0
	frame.largestAcknowledged = largestAcknowledged
	frame.ackBlocks = append(frame.ackBlocks, AckBlock{0, ackBlockLength})
	return frame
}

type StreamFrame struct {
	finBit bool
	streamIdLength uint8
	offsetLength uint8
	dataLengthPresent bool
	streamId uint32
	offset uint64
	dataLength uint16
	streamData []byte
}
func (frame StreamFrame) FrameType() FrameType { return StreamType }
func (frame StreamFrame) writeTo(buffer *bytes.Buffer) {
	typeByte := byte(frame.FrameType())
	if frame.finBit {
		typeByte |= 0x20
	}
	typeByte |= frame.streamIdLength << 3
	typeByte |= frame.offsetLength << 1
	if frame.dataLengthPresent {
		typeByte |= 1
	}
	binary.Write(buffer, binary.BigEndian, typeByte)
	switch frame.streamIdLength {
	case 0:
		binary.Write(buffer, binary.BigEndian, uint8(frame.streamId))
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(frame.streamId))
	case 2:
		//binary.Write(buffer, binary.BigEndian, [3]byte(frame.streamId))
		panic("TODO")
	case 3:
		binary.Write(buffer, binary.BigEndian, uint32(frame.streamId))
	}
	switch frame.offsetLength {
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(frame.offset))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(frame.offset))
	case 3:
		binary.Write(buffer, binary.BigEndian, frame.offset)
	}
	if frame.dataLengthPresent {
		binary.Write(buffer, binary.BigEndian, frame.dataLength)
	}
	binary.Write(buffer, binary.BigEndian, frame.streamData)
}
func ReadStreamFrame(buffer *bytes.Reader, conn *Connection) *StreamFrame {
	frame := new(StreamFrame)
	typeByte, _ := buffer.ReadByte()
	frame.finBit = (typeByte & 0x20) == 0x20
	frame.streamIdLength = (typeByte & 0x18) >> 3
	frame.offsetLength = (typeByte & 0x6) >> 1
	frame.dataLengthPresent = (typeByte & 0x1) == 1
	switch frame.streamIdLength {
	case 0:
		var id uint8
		binary.Read(buffer, binary.BigEndian, &id)
		frame.streamId = uint32(id)
	case 1:
		var id uint16
		binary.Read(buffer, binary.BigEndian, &id)
		frame.streamId = uint32(id)
	case 2:
		var id [3]byte
		binary.Read(buffer, binary.BigEndian, &id)
		frame.streamId = uint32((id[0] << 16) + (id[1] << 8) + id[2])
	case 3:
		binary.Read(buffer, binary.BigEndian, &frame.streamId)
	}
	switch frame.offsetLength {
	case 1:
		var offset uint16
		binary.Read(buffer, binary.BigEndian, &offset)
		frame.offset = uint64(offset)
	case 2:
		var offset uint32
		binary.Read(buffer, binary.BigEndian, &offset)
		frame.offset = uint64(offset)
	case 3:
		binary.Read(buffer, binary.BigEndian, &frame.offset)
	}

	if frame.dataLengthPresent {
		binary.Read(buffer, binary.BigEndian, &frame.dataLength)
	} else {
		panic(frame)
	}
	frame.streamData = make([]byte, frame.dataLength, frame.dataLength)
	buffer.Read(frame.streamData)

	stream, ok := conn.streams[frame.streamId]
	if !ok {
		panic(frame)
	}
	if frame.offset == stream.readOffset {
		stream.readOffset += uint64(frame.dataLength)
	}

	return frame
}
func NewStreamFrame(streamId uint32, stream *Stream, data []byte, finBit bool) *StreamFrame {
	frame := new(StreamFrame)
	frame.finBit = finBit
	frame.streamIdLength = 3  // TODO: Make a cleverer use of these
	frame.offsetLength = 3
	frame.dataLengthPresent = true
	frame.streamId = streamId
	frame.offset = stream.writeOffset
	frame.dataLength = uint16(len(data))
	frame.streamData = data
	stream.writeOffset += uint64(frame.dataLength)
	return frame
}
