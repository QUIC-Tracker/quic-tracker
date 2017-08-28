package main

type Frame interface {
	FrameType() FrameType
	toBytes() []byte
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
func (p *PaddingFrame) toBytes() []byte      { return []byte(p.FrameType()) }

type ResetStream struct {
	streamId    uint32
	errorCode   uint32
	finalOffset uint64
}
func (p *ResetStream) FrameType() FrameType { return ResetStreamType }
func (p *ResetStream) toBytes() []byte      { return nil }

type ConnectionCloseFrame struct {
	errorCode          uint32
	reasonPhraseLength uint16
	reasonPhrase       string
}
func (p *ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (p *ConnectionCloseFrame) toBytes() []byte      { return nil }

type MaxDataFrame struct {
	maximumData uint64
}
func (p *MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (p *MaxDataFrame) toBytes() []byte      { return nil }

type MaxStreamDataFrame struct {
	streamId uint32
	maximumStreamData uint64
}
func (p *MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (p *MaxStreamDataFrame) toBytes() []byte      { return nil }

type MaxStreamIdFrame struct {
	maximumStreamId uint32
}
func (p *MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (p *MaxStreamIdFrame) toBytes() []byte      { return nil }

type PingFrame byte
func (p *PingFrame) FrameType() FrameType { return PingType }
func (p *PingFrame) toBytes() []byte      { return nil }

type BlockedFrame byte
func (p *BlockedFrame) FrameType() FrameType { return BlockedType }
func (p *BlockedFrame) toBytes() []byte      { return nil }

type StreamBlockedFrame struct {
	streamId uint32
}
func (p *StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (p *StreamBlockedFrame) toBytes() []byte      { return nil }

type StreamIdNeededFrame byte
func (p *StreamIdNeededFrame) FrameType() FrameType { return StreamIdNeededType }
func (p *StreamIdNeededFrame) toBytes() []byte      { return nil }

type NewConnectionIdFrame struct {
	sequence            uint16
	connectionId        uint32
	statelessResetToken [8]byte
}
func (p *NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (p *NewConnectionIdFrame) toBytes() []byte      { return nil }

type StopSendingFrame struct {
	streamId  uint32
	errorCode uint32
}
func (p *StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (p *StopSendingFrame) toBytes() []byte      { return nil }

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
type AckBlock uint64
type Timestamp struct {
	deltaLargestAcknowledged uint8
	timeSince                uint16
}
func (p *AckFrame) FrameType() FrameType { return AckType }
func (p *AckFrame) toBytes() []byte      { return nil }

type StreamFrame struct {
	finBit bool
	streamIdLength uint8
	offsetLength uint8
	dataLengthPresent bool
	streamData []byte
}
func (p *StreamFrame) FrameType() FrameType { return StreamType }
func (p *StreamFrame) toBytes() []byte      { return nil }