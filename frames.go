package quictracker

import (
	"bytes"
	"encoding/binary"
	"io"
	"fmt"
	"errors"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
)

type Frame interface {
	FrameType() FrameType
	writeTo(buffer *bytes.Buffer)
	shouldBeRetransmitted() bool
	FrameLength() uint16
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
	case frameType == RetireConnectionIdType:
		return Frame(ReadRetireConnectionId(buffer)), nil
	case frameType == PathChallengeType:
		return Frame(ReadPathChallenge(buffer)), nil
	case frameType == PathResponseType:
		return Frame(ReadPathResponse(buffer)), nil
	case (frameType & StreamType) == StreamType && frameType <= 0x17:
		return Frame(ReadStreamFrame(buffer, conn)), nil
	case frameType == CryptoType:
		return Frame(ReadCryptoFrame(buffer, conn)), nil
	case frameType == NewTokenType:
		return Frame(ReadNewTokenFrame(buffer, conn)), nil
	case frameType == AckType:
		return Frame(ReadAckFrame(buffer)), nil
	case frameType == AckECNType:
		return Frame(ReadAckECNFrame(buffer, conn)), nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown frame type %d", typeByte))
	}
}
type FrameType uint64

const (
	PaddingFrameType     FrameType = 0x00
	ResetStreamType                = 0x01
	ConnectionCloseType            = 0x02
	ApplicationCloseType           = 0x03
	MaxDataType                    = 0x04
	MaxStreamDataType              = 0x05
	MaxStreamIdType                = 0x06
	PingType                       = 0x07
	BlockedType                    = 0x08
	StreamBlockedType              = 0x09
	StreamIdBlockedType            = 0x0a
	NewConnectionIdType            = 0x0b
	StopSendingType                = 0x0c
	RetireConnectionIdType		   = 0x0d
	PathChallengeType              = 0x0e
	PathResponseType               = 0x0f
	StreamType                     = 0x10
	CryptoType                     = 0x18
	NewTokenType                   = 0x19
	AckType                        = 0x1a
	AckECNType                     = 0x1b
)

type PaddingFrame byte

func (frame PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (frame PaddingFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
}
func (frame PaddingFrame) shouldBeRetransmitted() bool { return false }
func (frame PaddingFrame) FrameLength() uint16 { return 1 }
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
	WriteVarInt(buffer, frame.FinalOffset)
}
func (frame ResetStream) shouldBeRetransmitted() bool { return true }
func (frame ResetStream) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.StreamId) + 2 + VarIntLen(frame.FinalOffset)) }
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarIntValue(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	frame.FinalOffset, _ = ReadVarIntValue(buffer)
	return frame
}
type ConnectionCloseFrame struct {
	ErrorCode          uint16
	ErrorFrameType	   uint64
	ReasonPhraseLength uint64
	ReasonPhrase       string
}
func (frame ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (frame ConnectionCloseFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
	WriteVarInt(buffer, frame.ErrorFrameType)
	WriteVarInt(buffer, frame.ReasonPhraseLength)
	if frame.ReasonPhraseLength > 0 {
		buffer.Write([]byte(frame.ReasonPhrase))
	}
}
func (frame ConnectionCloseFrame) shouldBeRetransmitted() bool { return false }
func (frame ConnectionCloseFrame) FrameLength() uint16 { return 1 + 2 + uint16(VarIntLen(frame.ErrorFrameType) + VarIntLen(frame.ReasonPhraseLength)) + uint16(frame.ReasonPhraseLength) }
func NewConnectionCloseFrame(buffer *bytes.Reader) *ConnectionCloseFrame {
	frame := new(ConnectionCloseFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	frame.ErrorFrameType, _ = ReadVarIntValue(buffer)
	frame.ReasonPhraseLength, _ = ReadVarIntValue(buffer)
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	binary.Write(buffer, binary.BigEndian, frame.errorCode)
	WriteVarInt(buffer, frame.reasonPhraseLength)
	if frame.reasonPhraseLength > 0 {
		buffer.Write([]byte(frame.reasonPhrase))
	}
}
func (frame ApplicationCloseFrame) shouldBeRetransmitted() bool { return false }
func (frame ApplicationCloseFrame) FrameLength() uint16 { return 1 + 2 + uint16(VarIntLen(frame.reasonPhraseLength)) + uint16(frame.reasonPhraseLength) }
func NewApplicationCloseFrame(buffer *bytes.Reader) *ApplicationCloseFrame {
	frame := new(ApplicationCloseFrame)
	buffer.ReadByte()  // Discard frame type
	binary.Read(buffer, binary.BigEndian, &frame.errorCode)
	frame.reasonPhraseLength, _ = ReadVarIntValue(buffer)
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.MaximumData)
}
func (frame MaxDataFrame) shouldBeRetransmitted() bool { return true }
func (frame MaxDataFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.MaximumData)) }
func NewMaxDataFrame(buffer *bytes.Reader) *MaxDataFrame {
	frame := new(MaxDataFrame)
	buffer.ReadByte()  // Discard frame type
	frame.MaximumData, _ = ReadVarIntValue(buffer)
	return frame
}

type MaxStreamDataFrame struct {
	StreamId          uint64
	MaximumStreamData uint64
}
func (frame MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (frame MaxStreamDataFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.MaximumStreamData)
}
func (frame MaxStreamDataFrame) shouldBeRetransmitted() bool { return true }
func (frame MaxStreamDataFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.StreamId) + VarIntLen(frame.MaximumStreamData)) }
func NewMaxStreamDataFrame(buffer *bytes.Reader) *MaxStreamDataFrame {
	frame := new(MaxStreamDataFrame)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarIntValue(buffer)
	frame.MaximumStreamData, _ = ReadVarIntValue(buffer)
	return frame
}

type MaxStreamIdFrame struct {
	maximumStreamId uint64
}
func (frame MaxStreamIdFrame) FrameType() FrameType { return MaxStreamIdType }
func (frame MaxStreamIdFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.maximumStreamId)
}
func (frame MaxStreamIdFrame) shouldBeRetransmitted() bool { return true }
func (frame MaxStreamIdFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.maximumStreamId)) }
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamIdFrame {
	frame := new(MaxStreamIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.maximumStreamId, _ = ReadVarIntValue(buffer)
	return frame
}


type PingFrame byte
func (frame PingFrame) FrameType() FrameType { return PingType }
func (frame PingFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
}
func (frame PingFrame) shouldBeRetransmitted() bool { return true }
func (frame PingFrame) FrameLength() uint16 { return 1 }
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.offset)
}
func (frame BlockedFrame) shouldBeRetransmitted() bool { return true }
func (frame BlockedFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.offset)) }
func NewBlockedFrame(buffer *bytes.Reader) *BlockedFrame {
	frame := new(BlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.offset, _ = ReadVarIntValue(buffer)
	return frame
}

type StreamBlockedFrame struct {
	streamId uint64
	offset   uint64
}
func (frame StreamBlockedFrame) FrameType() FrameType { return StreamBlockedType }
func (frame StreamBlockedFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.streamId)
	WriteVarInt(buffer, frame.offset)
}
func (frame StreamBlockedFrame) shouldBeRetransmitted() bool { return true }
func (frame StreamBlockedFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.streamId) + VarIntLen(frame.offset)) }
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamBlockedFrame {
	frame := new(StreamBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarIntValue(buffer)
	frame.offset, _ = ReadVarIntValue(buffer)
	return frame
}

type StreamIdBlockedFrame struct {
	streamId uint64
}
func (frame StreamIdBlockedFrame) FrameType() FrameType { return StreamIdBlockedType }
func (frame StreamIdBlockedFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.streamId)
}
func (frame StreamIdBlockedFrame) shouldBeRetransmitted() bool { return true }
func (frame StreamIdBlockedFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.streamId)) }
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamIdBlockedFrame {
	frame := new(StreamIdBlockedFrame)
	buffer.ReadByte()  // Discard frame type
	frame.streamId, _ = ReadVarIntValue(buffer)
	return frame
}

type NewConnectionIdFrame struct {
	Length 			    uint8
	Sequence            uint64
	ConnectionId        []byte
	StatelessResetToken [16]byte
}
func (frame NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame NewConnectionIdFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	buffer.WriteByte(frame.Length)
	WriteVarInt(buffer, frame.Sequence)
	buffer.Write(frame.ConnectionId)
	binary.Write(buffer, binary.BigEndian, frame.StatelessResetToken)
}
func (frame NewConnectionIdFrame) shouldBeRetransmitted() bool { return true }
func (frame NewConnectionIdFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.Sequence)) + 1 + uint16(len(frame.ConnectionId)) + 16 }
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	buffer.ReadByte()  // Discard frame type
	frame.Length, _ = buffer.ReadByte()
	frame.Sequence, _ = ReadVarIntValue(buffer)
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	binary.Write(buffer, binary.BigEndian, frame.ErrorCode)
}
func (frame StopSendingFrame) shouldBeRetransmitted() bool { return true }
func (frame StopSendingFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.StreamId)) + 2 }
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
	buffer.ReadByte()  // Discard frame type
	frame.StreamId, _ = ReadVarIntValue(buffer)
	binary.Read(buffer, binary.BigEndian, &frame.ErrorCode)
	return frame
}

type RetireConnectionId struct {
	SequenceNumber uint64
}
func (frame RetireConnectionId) FrameType() FrameType { return RetireConnectionIdType }
func (frame RetireConnectionId) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.SequenceNumber)
}
func (frame RetireConnectionId) shouldBeRetransmitted() bool { return true }
func (frame RetireConnectionId) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.SequenceNumber)) }
func ReadRetireConnectionId(buffer *bytes.Reader) *RetireConnectionId {
	frame := new(RetireConnectionId)
	buffer.ReadByte()  // Discard frame byte
	frame.SequenceNumber, _ = ReadVarIntValue(buffer)
	return frame
}

type PathChallenge struct {
	Data [8]byte
}
func (frame PathChallenge) FrameType() FrameType { return PathChallengeType }
func (frame PathChallenge) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	buffer.Write(frame.Data[:])
}
func (frame PathChallenge) shouldBeRetransmitted() bool { return true }
func (frame PathChallenge) FrameLength() uint16 { return 1 + 8 }
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
	WriteVarInt(buffer, uint64(frame.FrameType()))
	buffer.Write(frame.Data[:])
}
func (frame PathResponse) shouldBeRetransmitted() bool { return false }
func (frame PathResponse) FrameLength() uint16 { return 1 + 8 }
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
	typeByte := uint64(frame.FrameType())
	if frame.FinBit {
		typeByte |= 0x01
	}
	if frame.LenBit {
		typeByte |= 0x02
	}
	if frame.OffBit {
		typeByte |= 0x04
	}
	WriteVarInt(buffer, typeByte)
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
func (frame StreamFrame) FrameLength() uint16 {
	length := 1 + uint16(VarIntLen(frame.StreamId))
	if frame.OffBit {
		length += uint16(VarIntLen(frame.Offset))
	}
	if frame.LenBit {
		length += uint16(VarIntLen(frame.Length))
	}
	return length + uint16(len(frame.StreamData))
}
func ReadStreamFrame(buffer *bytes.Reader, conn *Connection) *StreamFrame {
	frame := new(StreamFrame)
	typeByte, _ := buffer.ReadByte()
	frame.FinBit = (typeByte & 0x01) == 0x01
	frame.LenBit = (typeByte & 0x02) == 0x02
	frame.OffBit = (typeByte & 0x04) == 0x04

	frame.StreamId, _ = ReadVarIntValue(buffer)
	if frame.OffBit {
		frame.Offset, _ = ReadVarIntValue(buffer)
	}
	if frame.LenBit {
		frame.Length, _ = ReadVarIntValue(buffer)
	} else {
		frame.Length = uint64(buffer.Len())
	}
	frame.StreamData = make([]byte, frame.Length, frame.Length)
	buffer.Read(frame.StreamData)

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

type CryptoFrame struct {
	Offset     uint64
	Length     uint64
	CryptoData []byte
}
func (frame CryptoFrame) FrameType() FrameType { return CryptoType }
func (frame CryptoFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.Offset)
	WriteVarInt(buffer, frame.Length)
	buffer.Write(frame.CryptoData)
}
func (frame CryptoFrame) shouldBeRetransmitted() bool { return true }
func (frame CryptoFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(frame.Offset) + VarIntLen(frame.Length)) + uint16(len(frame.CryptoData))}
func ReadCryptoFrame(buffer *bytes.Reader, conn *Connection) *CryptoFrame {
	frame := new(CryptoFrame)
	ReadVarIntValue(buffer) // Discards frame type
	frame.Offset, _ = ReadVarIntValue(buffer)
	frame.Length, _ = ReadVarIntValue(buffer)
	frame.CryptoData = make([]byte, frame.Length)
	buffer.Read(frame.CryptoData)

	return frame
}
func NewCryptoFrame(cryptoStream *Stream, data []byte) *CryptoFrame {
	frame := &CryptoFrame{Offset: cryptoStream.WriteOffset, CryptoData: data, Length: uint64(len(data))}
	cryptoStream.WriteOffset += frame.Length
	cryptoStream.WriteData = append(cryptoStream.WriteData, data...)
	return frame
}

type NewTokenFrame struct {
	Token []byte
}
func (frame NewTokenFrame) FrameType() FrameType { return NewTokenType }
func (frame NewTokenFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, uint64(len(frame.Token)))
	buffer.Write(frame.Token)
}
func (frame NewTokenFrame) shouldBeRetransmitted() bool { return true }
func (frame NewTokenFrame) FrameLength() uint16 { return 1 + uint16(VarIntLen(uint64(len(frame.Token)))) + uint16(len(frame.Token))}
func ReadNewTokenFrame(buffer *bytes.Reader, conn *Connection) *NewTokenFrame {
	frame := new(NewTokenFrame)
	ReadVarIntValue(buffer) // Discard frame type
	tokenLength, _ := ReadVarIntValue(buffer)
	frame.Token = make([]byte, tokenLength)
	buffer.Read(frame.Token)
	return frame
}

type AckFrame struct {
	LargestAcknowledged PacketNumber
	AckDelay            uint64
	AckBlockCount       uint64
	AckBlocks           []AckBlock
}
type AckBlock struct {
	Gap   uint64
	Block uint64
}
func (frame AckFrame) FrameType() FrameType { return AckType }
func (frame AckFrame) shouldBeRetransmitted() bool { return false }
func (frame AckFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, uint64(frame.LargestAcknowledged))
	WriteVarInt(buffer, frame.AckDelay)
	WriteVarInt(buffer, frame.AckBlockCount)
	for i, ack := range frame.AckBlocks {
		if i > 0 {
			WriteVarInt(buffer, ack.Gap)
		}
		WriteVarInt(buffer, ack.Block)
	}
}
func (frame AckFrame) FrameLength() uint16 {
	var length uint16
	length += 1 + uint16(VarIntLen(uint64(frame.LargestAcknowledged)) + VarIntLen(frame.AckDelay) + VarIntLen(frame.AckBlockCount))

	for i, ack := range frame.AckBlocks {
		if i > 0 {
			length += uint16(VarIntLen(ack.Gap))
		}
		length += uint16(VarIntLen(ack.Block))
	}
	return length
}
func (frame AckFrame) GetAckedPackets() []PacketNumber {  // TODO: This is prone to livelock
	var packets []PacketNumber

	currentPacketNumber := frame.LargestAcknowledged
	packets = append(packets, currentPacketNumber)
	for i := uint64(0); i < frame.AckBlocks[0].Block; i++ {
		currentPacketNumber--
		packets = append(packets, currentPacketNumber)
	}
	for _, ackBlock := range frame.AckBlocks[1:] {
		for i := uint64(0); i <= ackBlock.Gap; i++ { // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.Block; i++ {
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
	}
	return packets
}
func ReadAckFrame(buffer *bytes.Reader) *AckFrame {
	frame := new(AckFrame)
	buffer.ReadByte()  // Discard frame byte

	frame.LargestAcknowledged = ReadPacketNumber(buffer)
	frame.AckDelay, _ = ReadVarIntValue(buffer)
	frame.AckBlockCount, _ = ReadVarIntValue(buffer)

	firstBlock := AckBlock{}
	firstBlock.Block, _ = ReadVarIntValue(buffer)
	frame.AckBlocks = append(frame.AckBlocks, firstBlock)

	var i uint64
	for i = 0; i < frame.AckBlockCount; i++ {
		ack := AckBlock{}
		ack.Gap, _ = ReadVarIntValue(buffer)
		ack.Block, _ = ReadVarIntValue(buffer)
		frame.AckBlocks = append(frame.AckBlocks, ack)
	}
	return frame
}

type AckECNFrame struct {
	AckFrame
	ECT0Count uint64
	ECT1Count uint64
	ECTCECount uint64
}
func (frame AckECNFrame) FrameType() FrameType { return AckECNType }
func (frame AckECNFrame) writeTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, uint64(frame.LargestAcknowledged))
	WriteVarInt(buffer, frame.AckDelay)
	WriteVarInt(buffer, frame.AckBlockCount)
	for i, ack := range frame.AckBlocks {
		if i > 0 {
			WriteVarInt(buffer, ack.Gap)
		}
		WriteVarInt(buffer, ack.Block)
	}
	WriteVarInt(buffer, frame.ECT0Count)
	WriteVarInt(buffer, frame.ECT1Count)
	WriteVarInt(buffer, frame.ECTCECount)
}
func (frame AckECNFrame) shouldBeRetransmitted() bool { return true }
func (frame AckECNFrame) FrameLength() uint16 { return frame.AckFrame.FrameLength() + uint16(VarIntLen(frame.ECT0Count) + VarIntLen(frame.ECT1Count) + VarIntLen(frame.ECTCECount))}
func ReadAckECNFrame(buffer *bytes.Reader, conn *Connection) *AckECNFrame {
	frame := &AckECNFrame{*ReadAckFrame(buffer), 0, 0, 0}

	frame.ECT0Count, _ = ReadVarIntValue(buffer)
	frame.ECT1Count, _ = ReadVarIntValue(buffer)
	frame.ECTCECount, _ = ReadVarIntValue(buffer)
	return frame
}