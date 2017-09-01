package main

import (
	"bytes"
	"encoding/binary"
)

type Frame interface {
	FrameType() FrameType
	writeTo(buffer *bytes.Buffer)
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

func (frame *PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (frame *PaddingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewPaddingFrame(buffer *bytes.Reader) *PaddingFrame {
	return new(PaddingFrame)
}

type ResetStream struct {
	streamId    uint32
	errorCode   uint32
	finalOffset uint64
}
func (frame *ResetStream) FrameType() FrameType { return ResetStreamType }
func (frame *ResetStream) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	binary.Write(buffer, binary.BigEndian, frame.finalOffset)
}
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
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
func (frame *ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (frame *ConnectionCloseFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	binary.Write(buffer, binary.BigEndian, frame.reasonPhraseLength)
	if frame.reasonPhraseLength > 0 {
		buffer.Write([]byte(frame.reasonPhrase))
	}
}
func NewConnectionCloseFrame(buffer *bytes.Reader) *ConnectionCloseFrame {
	frame := new(ConnectionCloseFrame)
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	binary.Read(buffer, binary.BigEndian, &frame.reasonPhraseLength)
	if frame.reasonPhraseLength {
		var reasonBytes [frame.reasonPhraseLength]string
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.reasonPhrase = string(reasonBytes)
	}
	return frame
}


type MaxDataFrame struct {
	maximumData uint64
}
func (frame *MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (frame *MaxDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.maximumData)
}
func NewMaxDataFrame(buffer *bytes.Reader) *MaxDataFrame {
	frame := new(MaxDataFrame)
	binary.Read(buffer, binary.BigEndian, &frame.maximumData)
	return frame
}

type MaxStreamDataFrame struct {
	streamId uint32
	maximumStreamData uint64
}
func (frame *MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (frame *MaxStreamDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.maximumStreamData)
}
func NewMaxStreamDataFrame(buffer *bytes.Reader) *MaxStreamDataFrame {
	frame := new(MaxStreamDataFrame)
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	binary.Read(buffer, binary.BigEndian, &frame.maximumStreamData)
	return frame
}

type MaxStreamIdFrame struct {
	maximumStreamId uint32
}
func (frame *MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (frame *MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.maximumStreamId)
}
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	binary.Read(buffer, binary.BigEndian, &frame.maximumStreamId)
	return frame
}


type PingFrame byte
func (frame *PingFrame) FrameType() FrameType { return PingType }
func (frame *PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	return new(PingFrame)
}

type BlockedFrame byte
func (frame *BlockedFrame) FrameType() FrameType { return BlockedType }
func (frame *BlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewBlockedFrame(buffer *bytes.Reader) *BlockedFrame {
	return new(BlockedFrame)
}

type StreamBlockedFrame struct {
	streamId uint32
}
func (frame *StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (frame *StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
}
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamBlockedFrame {
	frame := new(StreamBlockedFrame)
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	return frame
}

type StreamIdNeededFrame byte
func (frame *StreamIdNeededFrame) FrameType() FrameType { return StreamIdNeededType }
func (frame *StreamIdNeededFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
}
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdNeededFrame {
	return new(StreamIdNeededFrame)
}

type NewConnectionIdFrame struct {
	sequence            uint16
	connectionId        uint32
	statelessResetToken [8]byte
}
func (frame *NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame *NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.sequence)
	binary.Write(buffer, binary.BigEndian, frame.connectionId)
	binary.Write(buffer, binary.BigEndian, frame.statelessResetToken)
}
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	binary.Read(buffer, binary.BigEndian, &frame.sequence)
	binary.Read(buffer, binary.BigEndian, &frame.connectionId)
	binary.Read(buffer, binary.BigEndian, &frame.statelessResetToken)
	return frame
}

type StopSendingFrame struct {
	streamId  uint32
	errorCode uint32
}
func (frame *StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (frame *StopSendingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, frame.FrameType())
	binary.Write(buffer, binary.BigEndian, frame.streamId)
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
}
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
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
func (frame *AckFrame) FrameType() FrameType { return AckType }
func (frame *AckFrame) writeTo(buffer *bytes.Buffer) {
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
		binary.Write(buffer, binary.BigEndian, block.ack)
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
func NewAckFrame(buffer *bytes.Reader) *AckFrame {
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
	for i := 0; i < int(frame.numAckBlocks); i++ {
		ack := AckBlock{}
		if i > 0 {
			ack.gap, _ = buffer.ReadByte()
		}
		binary.Read(buffer, binary.BigEndian, &ack.ack)
		frame.ackBlocks = append(frame.ackBlocks, ack)
	}
	for i:= 0; i < int(frame.numTimestamps); i++ {
		timestamp := Timestamp{}
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
func (frame *StreamFrame) FrameType() FrameType { return StreamType }
func (frame *StreamFrame) writeTo(buffer *bytes.Buffer) {
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
		binary.Write(buffer, binary.BigEndian, [3]byte(frame.streamId))
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
func NewStreamFrame(buffer *bytes.Reader) *StreamFrame {
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
		frame.streamId = uint32(id)
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
	var data [frame.dataLength]byte
	binary.Read(buffer, binary.BigEndian, data)
	return frame
}
