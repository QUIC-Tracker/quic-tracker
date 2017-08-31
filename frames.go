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

type MaxDataFrame struct {
	maximumData uint64
}
func (p *MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (p *MaxDataFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.maximumData)
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

type MaxStreamIdFrame struct {
	maximumStreamId uint32
}
func (p *MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (p *MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.maximumStreamId)
}


type PingFrame byte
func (p *PingFrame) FrameType() FrameType { return PingType }
func (p *PingFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}

type BlockedFrame byte
func (p *BlockedFrame) FrameType() FrameType { return BlockedType }
func (p *BlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
}


type StreamBlockedFrame struct {
	streamId uint32
}
func (p *StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (p *StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
	binary.Write(buffer, binary.BigEndian, p.streamId)
}

type StreamIdNeededFrame byte
func (p *StreamIdNeededFrame) FrameType() FrameType { return StreamIdNeededType }
func (p *StreamIdNeededFrame) writeTo(buffer *bytes.Buffer) {
	binary.Write(buffer, binary.BigEndian, p.FrameType())
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
	buffer.Write([]byte(p.statelessResetToken))
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
		binary.Write(buffer, binary.BigEndian, uint8(p.largestAcknowledgedLength))
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(p.largestAcknowledgedLength))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(p.largestAcknowledgedLength))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint64(p.largestAcknowledgedLength))
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

type StreamFrame struct {
	finBit bool
	streamIdLength uint8
	offsetLength uint8
	dataLengthPresent bool
	streamId uint32
	offset uint32
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
		binary.Write(buffer, binary.BigEndian, uint32(p.streamId))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint64(p.streamId))
	}
	switch p.offsetLength {
	case 1:
		binary.Write(buffer, binary.BigEndian, uint16(p.offset))
	case 2:
		binary.Write(buffer, binary.BigEndian, uint32(p.offset))
	case 3:
		binary.Write(buffer, binary.BigEndian, uint64(p.offset))
	}
	if p.dataLengthPresent {
		binary.Write(buffer, binary.BigEndian, p.dataLength)
	}
	binary.Write(buffer, binary.BigEndian, p.streamData)
}

