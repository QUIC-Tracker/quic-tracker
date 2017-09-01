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

func (p *PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (p *PaddingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}
func NewPaddingFrame(buffer *bytes.Reader) *PaddingFrame {
	return new(PaddingFrame)
}

type ResetStream struct {
	streamId    uint32
	errorCode   uint32
	finalOffset uint64
}
func (p *ResetStream) FrameType() FrameType { return ResetStreamType }
func (p *ResetStream) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.streamId)
	binary.Write(buffer, binary.BigEndian, p.errorCode)
	binary.Write(buffer, binary.BigEndian, p.finalOffset)
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
func (p *ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (p *ConnectionCloseFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.errorCode)
	binary.Write(buffer, binary.BigEndian, p.reasonPhraseLength)
	if p.reasonPhraseLength > 0 {
		buffer.Write([]byte(p.reasonPhrase))
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
func (p *MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (p *MaxDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.maximumData)
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
func (p *MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (p *MaxStreamDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.streamId)
	binary.Write(buffer, binary.BigEndian, p.maximumStreamData)
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
func (p *MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (p *MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.maximumStreamId)
}
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	binary.Read(buffer, binary.BigEndian, &frame.maximumStreamId)
	return frame
}


type PingFrame byte
func (p *PingFrame) FrameType() FrameType { return PingType }
func (p *PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	return new(PingFrame)
}

type BlockedFrame byte
func (p *BlockedFrame) FrameType() FrameType { return BlockedType }
func (p *BlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}
func NewBlockedFrame(buffer *bytes.Reader) *BlockedFrame {
	return new(BlockedFrame)
}

type StreamBlockedFrame struct {
	streamId uint32
}
func (p *StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (p *StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.streamId)
}
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamBlockedFrame {
	frame := new(StreamBlockedFrame)
	binary.Read(buffer, binary.BigEndian, &frame.streamId)
	return frame
}

type StreamIdNeededFrame byte
func (p *StreamIdNeededFrame) FrameType() FrameType { return StreamIdNeededType }
func (p *StreamIdNeededFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdNeededFrame {
	return new(StreamIdNeededFrame)
}

type NewConnectionIdFrame struct {
	sequence            uint16
	connectionId        uint32
	statelessResetToken [8]byte
}
func (p *NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (p *NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.sequence)
	binary.Write(buffer, binary.BigEndian, p.connectionId)
	binary.Write(buffer, binary.BigEndian, p.statelessResetToken)
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
func (p *StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (p *StopSendingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.streamId)
	binary.Write(buffer, binary.BigEndian, p.errorCode)
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
func (p *AckFrame) FrameType() FrameType { return AckType }
func (p *AckFrame) writeTo(buffer *bytes.Buffer) {
	typeByte := byte(p.FrameType())
	if p.numBlocksPresent {
		typeByte |= 0x10
	}
	typeByte |= p.largestAcknowledgedLength << 2
	typeByte |= p.AckBlockLength
	binary.Write(buffer, binary.BigEndian, typeByte)
	if p.numBlocksPresent {
		binary.Write(buffer, binary.BigEndian, p.numAckBlocks)
	}
	binary.Write(buffer, binary.BigEndian, p.numTimestamps)
	switch p.largestAcknowledgedLength {
	case 0:
		binary.Write(buffer, binary.BigEndian, uint8(p.largestAcknowledged))
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(p.largestAcknowledged))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(p.largestAcknowledged))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint64(p.largestAcknowledged))
	}
	binary.Write(buffer, binary.BigEndian, p.ackDelay)
	for index, block := range p.ackBlocks {
		if index > 0 {
			binary.Write(buffer, binary.BigEndian, block.gap)
		}
		binary.Write(buffer, binary.BigEndian, block.ack)
	}
	for index, timestamp := range p.timestamps {
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
func (p *StreamFrame) FrameType() FrameType { return StreamType }
func (p *StreamFrame) writeTo(buffer *bytes.Buffer) {
	typeByte := byte(p.FrameType())
	if p.finBit {
		typeByte |= 0x20
	}
	typeByte |= p.streamIdLength << 3
	typeByte |= p.offsetLength << 1
	if p.dataLengthPresent {
		typeByte |= 1
	}
	binary.Write(buffer, binary.BigEndian, typeByte)
	switch p.streamIdLength {
	case 0:
		binary.Write(buffer, binary.BigEndian, uint8(p.streamId))
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(p.streamId))
	case 2:
		binary.Write(buffer, binary.BigEndian, [3]byte(p.streamId))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint32(p.streamId))
	}
	switch p.offsetLength {
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(p.offset))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(p.offset))
	case 3:
		binary.Write(buffer, binary.BigEndian, p.offset)
	}
	if p.dataLengthPresent {
		binary.Write(buffer, binary.BigEndian, p.dataLength)
	}
	binary.Write(buffer, binary.BigEndian, p.streamData)
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
