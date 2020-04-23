package quictracker

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
	"io"
)

type Frame interface {
	FrameType() FrameType
	WriteTo(buffer *bytes.Buffer)
	shouldBeRetransmitted() bool
	FrameLength() uint16
}

func NewFrame(buffer *bytes.Reader, conn *Connection) (Frame, error) {
	typeValue, length,  err := ReadVarIntValue(buffer)
	if err == io.EOF {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	for i := 0; i < length; i++ {
		err := buffer.UnreadByte()
		if err != nil {
			return nil, err
		}
	}
	frameType := FrameType(typeValue)
	switch {
	case frameType == PaddingFrameType:
		return Frame(NewPaddingFrame(buffer)), nil
	case frameType == PingType:
		return Frame(NewPingFrame(buffer)), nil
	case frameType == AckType:
		return Frame(ReadAckFrame(buffer)), nil
	case frameType == AckECNType:
		return Frame(ReadAckECNFrame(buffer, conn)), nil
	case frameType == ResetStreamType:
		return Frame(NewResetStream(buffer)), nil
	case frameType == StopSendingType:
		return Frame(NewStopSendingFrame(buffer)), nil
	case frameType == CryptoType:
		return Frame(ReadCryptoFrame(buffer, conn)), nil
	case frameType == NewTokenType:
		return Frame(ReadNewTokenFrame(buffer, conn)), nil
	case (frameType&StreamType) == StreamType && frameType <= 0x0f:
		return Frame(ReadStreamFrame(buffer, conn)), nil
	case frameType == MaxDataType:
		return Frame(NewMaxDataFrame(buffer)), nil
	case frameType == MaxStreamDataType:
		return Frame(NewMaxStreamDataFrame(buffer)), nil
	case frameType&0xFE == MaxStreamsType:
		return Frame(NewMaxStreamIdFrame(buffer)), nil
	case frameType == DataBlockedType:
		return Frame(NewBlockedFrame(buffer)), nil
	case frameType == StreamDataBlockedType:
		return Frame(NewStreamBlockedFrame(buffer)), nil
	case frameType&0xFE == StreamsBlockedType:
		return Frame(NewStreamIdNeededFrame(buffer)), nil
	case frameType == NewConnectionIdType:
		return Frame(NewNewConnectionIdFrame(buffer)), nil
	case frameType == RetireConnectionIdType:
		return Frame(ReadRetireConnectionId(buffer)), nil
	case frameType == PathChallengeType:
		return Frame(ReadPathChallenge(buffer)), nil
	case frameType == PathResponseType:
		return Frame(ReadPathResponse(buffer)), nil
	case frameType == ConnectionCloseType:
		return Frame(NewConnectionCloseFrame(buffer)), nil
	case frameType == ApplicationCloseType:
		return Frame(NewApplicationCloseFrame(buffer)), nil
	case frameType == HandshakeDoneType:
		return Frame(NewHandshakeDoneFrame(buffer)), nil
	default:
		return nil, errors.New(fmt.Sprintf("Unknown frame type %d", typeValue))
	}
}

type FrameType uint64

const (
	PaddingFrameType       FrameType = 0x00
	PingType                         = 0x01
	AckType                          = 0x02
	AckECNType                       = 0x03
	ResetStreamType                  = 0x04
	StopSendingType                  = 0x05
	CryptoType                       = 0x06
	NewTokenType                     = 0x07
	StreamType                       = 0x08
	MaxDataType                      = 0x10
	MaxStreamDataType                = 0x11
	MaxStreamsType                   = 0x12
	DataBlockedType                  = 0x14
	StreamDataBlockedType            = 0x15
	StreamsBlockedType               = 0x16
	NewConnectionIdType              = 0x18
	RetireConnectionIdType           = 0x19
	PathChallengeType                = 0x1a
	PathResponseType                 = 0x1b
	ConnectionCloseType              = 0x1c
	ApplicationCloseType             = 0x1d
	HandshakeDoneType				 = 0x1e
)

type PaddingFrame byte

func (frame *PaddingFrame) FrameType() FrameType { return PaddingFrameType }
func (frame *PaddingFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
}
func (frame *PaddingFrame) shouldBeRetransmitted() bool { return false }
func (frame *PaddingFrame) FrameLength() uint16         { return 1 }
func NewPaddingFrame(buffer *bytes.Reader) *PaddingFrame {
	_, _ = ReadVarInt(buffer) // Discard frame type
	return new(PaddingFrame)
}

type PingFrame byte

func (frame *PingFrame) FrameType() FrameType { return PingType }
func (frame *PingFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
}
func (frame *PingFrame) shouldBeRetransmitted() bool { return false }
func (frame *PingFrame) FrameLength() uint16         { return 1 }
func NewPingFrame(buffer *bytes.Reader) *PingFrame {
	frame := new(PingFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	return frame
}

type AckFrame struct {
	LargestAcknowledged PacketNumber
	AckDelay            uint64
	AckRangeCount       uint64
	AckRanges           []AckRange
}
type AckRange struct {
	Gap      uint64
	AckRange uint64
}

func (frame *AckFrame) FrameType() FrameType        { return AckType }
func (frame *AckFrame) shouldBeRetransmitted() bool { return false }
func (frame *AckFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, uint64(frame.LargestAcknowledged))
	WriteVarInt(buffer, frame.AckDelay)
	WriteVarInt(buffer, frame.AckRangeCount)
	for i, ack := range frame.AckRanges {
		if i > 0 {
			WriteVarInt(buffer, ack.Gap)
		}
		WriteVarInt(buffer, ack.AckRange)
	}
}
func (frame *AckFrame) FrameLength() uint16 {
	var length uint16
	length += 1 + uint16(VarIntLen(uint64(frame.LargestAcknowledged))+VarIntLen(frame.AckDelay)+VarIntLen(frame.AckRangeCount))

	for i, ack := range frame.AckRanges {
		if i > 0 {
			length += uint16(VarIntLen(ack.Gap))
		}
		length += uint16(VarIntLen(ack.AckRange))
	}
	return length
}
func (frame *AckFrame) GetAckedPackets() []PacketNumber { // TODO: This is prone to livelock
	var packets []PacketNumber

	currentPacketNumber := frame.LargestAcknowledged
	packets = append(packets, currentPacketNumber)
	for i := uint64(0); i < frame.AckRanges[0].AckRange; i++ {
		currentPacketNumber--
		packets = append(packets, currentPacketNumber)
	}
	for _, ackBlock := range frame.AckRanges[1:] {
		for i := uint64(0); i <= ackBlock.Gap; i++ { // See https://tools.ietf.org/html/draft-ietf-quic-transport-10#section-8.15.1
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
		for i := uint64(0); i < ackBlock.AckRange; i++ {
			currentPacketNumber--
			packets = append(packets, currentPacketNumber)
		}
	}
	return packets
}
func ReadAckFrame(buffer *bytes.Reader) *AckFrame {
	frame := new(AckFrame)
	buffer.ReadByte() // Discard frame byte

	frame.LargestAcknowledged = ReadPacketNumber(buffer)
	frame.AckDelay, _, _ = ReadVarIntValue(buffer)
	frame.AckRangeCount, _, _ = ReadVarIntValue(buffer)

	firstBlock := AckRange{}
	firstBlock.AckRange, _, _ = ReadVarIntValue(buffer)
	frame.AckRanges = append(frame.AckRanges, firstBlock)

	var i uint64
	for i = 0; i < frame.AckRangeCount; i++ {
		ack := AckRange{}
		ack.Gap, _, _ = ReadVarIntValue(buffer)
		ack.AckRange, _, _ = ReadVarIntValue(buffer)
		frame.AckRanges = append(frame.AckRanges, ack)
	}
	return frame
}

type AckECNFrame struct {
	AckFrame
	ECT0Count  uint64
	ECT1Count  uint64
	ECTCECount uint64
}

func (frame *AckECNFrame) FrameType() FrameType { return AckECNType }
func (frame *AckECNFrame) WriteTo(buffer *bytes.Buffer) {
	frame.AckFrame.WriteTo(buffer)
	WriteVarInt(buffer, frame.ECT0Count)
	WriteVarInt(buffer, frame.ECT1Count)
	WriteVarInt(buffer, frame.ECTCECount)
}
func (frame *AckECNFrame) shouldBeRetransmitted() bool { return false }
func (frame *AckECNFrame) FrameLength() uint16         { return frame.AckFrame.FrameLength() + uint16(VarIntLen(frame.ECT0Count)+VarIntLen(frame.ECT1Count)+VarIntLen(frame.ECTCECount)) }
func ReadAckECNFrame(buffer *bytes.Reader, conn *Connection) *AckECNFrame {
	frame := &AckECNFrame{*ReadAckFrame(buffer), 0, 0, 0}

	frame.ECT0Count, _, _ = ReadVarIntValue(buffer)
	frame.ECT1Count, _, _ = ReadVarIntValue(buffer)
	frame.ECTCECount, _, _ = ReadVarIntValue(buffer)
	return frame
}

type ResetStream struct {
	StreamId             uint64
	ApplicationErrorCode uint64
	FinalSize            uint64
}

func (frame *ResetStream) FrameType() FrameType { return ResetStreamType }
func (frame *ResetStream) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.ApplicationErrorCode)
	WriteVarInt(buffer, frame.FinalSize)
}
func (frame *ResetStream) shouldBeRetransmitted() bool { return true }
func (frame *ResetStream) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.StreamId)+VarIntLen(frame.ApplicationErrorCode)+VarIntLen(frame.FinalSize)) }
func NewResetStream(buffer *bytes.Reader) *ResetStream {
	frame := new(ResetStream)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamId, _, _ = ReadVarIntValue(buffer)
	frame.ApplicationErrorCode, _, _ = ReadVarIntValue(buffer)
	frame.FinalSize, _, _ = ReadVarIntValue(buffer)
	return frame
}

type StopSendingFrame struct {
	StreamId             uint64
	ApplicationErrorCode uint64
}

func (frame *StopSendingFrame) FrameType() FrameType { return StopSendingType }
func (frame *StopSendingFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.ApplicationErrorCode)
}
func (frame *StopSendingFrame) shouldBeRetransmitted() bool { return true }
func (frame *StopSendingFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.StreamId) + VarIntLen(frame.ApplicationErrorCode)) }
func NewStopSendingFrame(buffer *bytes.Reader) *StopSendingFrame {
	frame := new(StopSendingFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamId, _, _ = ReadVarIntValue(buffer)
	frame.ApplicationErrorCode, _, _ = ReadVarIntValue(buffer)
	return frame
}

type CryptoFrame struct {
	Offset     uint64
	Length     uint64
	CryptoData []byte
}

func (frame *CryptoFrame) FrameType() FrameType { return CryptoType }
func (frame *CryptoFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.Offset)
	WriteVarInt(buffer, frame.Length)
	buffer.Write(frame.CryptoData)
}
func (frame *CryptoFrame) shouldBeRetransmitted() bool { return true }
func (frame *CryptoFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.Offset)+VarIntLen(frame.Length)) + uint16(len(frame.CryptoData)) }
func ReadCryptoFrame(buffer *bytes.Reader, conn *Connection) *CryptoFrame {
	frame := new(CryptoFrame)
	ReadVarIntValue(buffer) // Discards frame type
	frame.Offset, _, _ = ReadVarIntValue(buffer)
	frame.Length, _, _ = ReadVarIntValue(buffer)
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

func (frame *NewTokenFrame) FrameType() FrameType { return NewTokenType }
func (frame *NewTokenFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, uint64(len(frame.Token)))
	buffer.Write(frame.Token)
}
func (frame *NewTokenFrame) shouldBeRetransmitted() bool { return true }
func (frame *NewTokenFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(uint64(len(frame.Token)))) + uint16(len(frame.Token)) }
func ReadNewTokenFrame(buffer *bytes.Reader, conn *Connection) *NewTokenFrame {
	frame := new(NewTokenFrame)
	ReadVarIntValue(buffer) // Discard frame type
	tokenLength, _, _ := ReadVarIntValue(buffer)
	frame.Token = make([]byte, tokenLength)
	buffer.Read(frame.Token)
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

func (frame *StreamFrame) FrameType() FrameType { return StreamType }
func (frame *StreamFrame) WriteTo(buffer *bytes.Buffer) {
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
func (frame *StreamFrame) shouldBeRetransmitted() bool { return true }
func (frame *StreamFrame) FrameLength() uint16 {
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

	frame.StreamId, _, _ = ReadVarIntValue(buffer)
	if frame.OffBit {
		frame.Offset, _, _ = ReadVarIntValue(buffer)
	}
	if frame.LenBit {
		frame.Length, _, _ = ReadVarIntValue(buffer)
	} else {
		frame.Length = uint64(buffer.Len())
	}
	frame.StreamData = make([]byte, frame.Length, frame.Length)
	buffer.Read(frame.StreamData)

	conn.Streams.Get(frame.StreamId).addToRead(frame)

	return frame
}
func NewStreamFrame(streamId, offset uint64, data []byte, finBit bool) *StreamFrame {
	frame := new(StreamFrame)
	frame.StreamId = streamId
	frame.FinBit = finBit
	frame.LenBit = true
	frame.Offset = offset
	frame.OffBit = frame.Offset > 0
	frame.Length = uint64(len(data))
	frame.StreamData = data
	return frame
}

type MaxDataFrame struct {
	MaximumData uint64
}

func (frame *MaxDataFrame) FrameType() FrameType { return MaxDataType }
func (frame *MaxDataFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.MaximumData)
}
func (frame *MaxDataFrame) shouldBeRetransmitted() bool { return true }
func (frame *MaxDataFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.MaximumData)) }
func NewMaxDataFrame(buffer *bytes.Reader) *MaxDataFrame {
	frame := new(MaxDataFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.MaximumData, _, _ = ReadVarIntValue(buffer)
	return frame
}

type MaxStreamDataFrame struct {
	StreamId          uint64
	MaximumStreamData uint64
}

func (frame *MaxStreamDataFrame) FrameType() FrameType { return MaxStreamDataType }
func (frame *MaxStreamDataFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.MaximumStreamData)
}
func (frame *MaxStreamDataFrame) shouldBeRetransmitted() bool { return true }
func (frame *MaxStreamDataFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.StreamId)+VarIntLen(frame.MaximumStreamData)) }
func NewMaxStreamDataFrame(buffer *bytes.Reader) *MaxStreamDataFrame {
	frame := new(MaxStreamDataFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamId, _, _ = ReadVarIntValue(buffer)
	frame.MaximumStreamData, _, _ = ReadVarIntValue(buffer)
	return frame
}

type MaxStreamsFrame struct {
	StreamsType    StreamsType
	MaximumStreams uint64
}

func (frame *MaxStreamsFrame) FrameType() FrameType {
	if frame.StreamsType == BidiStreams {
		return MaxStreamsType
	} else {
		return MaxStreamsType + 1
	}
}
func (frame *MaxStreamsFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.MaximumStreams)
}
func (frame *MaxStreamsFrame) shouldBeRetransmitted() bool { return true }
func (frame *MaxStreamsFrame) IsUni() bool                 { return frame.StreamsType == UniStreams }
func (frame *MaxStreamsFrame) IsBidi() bool                { return frame.StreamsType == BidiStreams }
func (frame *MaxStreamsFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.MaximumStreams)) }
func NewMaxStreamIdFrame(buffer *bytes.Reader) *MaxStreamsFrame {
	frame := new(MaxStreamsFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.MaximumStreams, _, _ = ReadVarIntValue(buffer)
	return frame
}

type DataBlockedFrame struct {
	DataLimit uint64
}

func (frame *DataBlockedFrame) FrameType() FrameType { return DataBlockedType }
func (frame *DataBlockedFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.DataLimit)
}
func (frame *DataBlockedFrame) shouldBeRetransmitted() bool { return false }
func (frame *DataBlockedFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.DataLimit)) }
func NewBlockedFrame(buffer *bytes.Reader) *DataBlockedFrame {
	frame := new(DataBlockedFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.DataLimit, _, _ = ReadVarIntValue(buffer)
	return frame
}

type StreamDataBlockedFrame struct {
	StreamId        uint64
	StreamDataLimit uint64
}

func (frame *StreamDataBlockedFrame) FrameType() FrameType { return StreamDataBlockedType }
func (frame *StreamDataBlockedFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamId)
	WriteVarInt(buffer, frame.StreamDataLimit)
}
func (frame *StreamDataBlockedFrame) shouldBeRetransmitted() bool { return false }
func (frame *StreamDataBlockedFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.StreamId)+VarIntLen(frame.StreamDataLimit)) }
func NewStreamBlockedFrame(buffer *bytes.Reader) *StreamDataBlockedFrame {
	frame := new(StreamDataBlockedFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamId, _, _ = ReadVarIntValue(buffer)
	frame.StreamDataLimit, _, _ = ReadVarIntValue(buffer)
	return frame
}

type StreamsBlockedFrame struct {
	StreamsType StreamsType
	StreamLimit uint64
}

func (frame *StreamsBlockedFrame) FrameType() FrameType {
	if frame.StreamsType == BidiStreams {
		return StreamsBlockedType
	} else {
		return StreamsBlockedType + 1
	}
}
func (frame *StreamsBlockedFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.StreamLimit)
}
func (frame *StreamsBlockedFrame) shouldBeRetransmitted() bool { return false }
func (frame *StreamsBlockedFrame) IsUni() bool                 { return frame.StreamsType == UniStreams }
func (frame *StreamsBlockedFrame) IsBidi() bool                { return frame.StreamsType == BidiStreams }
func (frame *StreamsBlockedFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.StreamLimit)) }
func NewStreamIdNeededFrame(buffer *bytes.Reader) *StreamsBlockedFrame {
	frame := new(StreamsBlockedFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.StreamLimit, _, _ = ReadVarIntValue(buffer)
	return frame
}

type NewConnectionIdFrame struct {
	Sequence            uint64
	RetirePriorTo		uint64
	Length              uint8
	ConnectionId        []byte
	StatelessResetToken [16]byte
}

func (frame *NewConnectionIdFrame) FrameType() FrameType { return NewConnectionIdType }
func (frame *NewConnectionIdFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.Sequence)
	WriteVarInt(buffer, frame.RetirePriorTo)
	buffer.WriteByte(frame.Length)
	buffer.Write(frame.ConnectionId)
	binary.Write(buffer, binary.BigEndian, frame.StatelessResetToken)
}
func (frame *NewConnectionIdFrame) shouldBeRetransmitted() bool { return true }
func (frame *NewConnectionIdFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.Sequence) + VarIntLen(frame.RetirePriorTo)) + 1 + uint16(len(frame.ConnectionId)) + 16 }
func NewNewConnectionIdFrame(buffer *bytes.Reader) *NewConnectionIdFrame {
	frame := new(NewConnectionIdFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.Sequence, _, _ = ReadVarIntValue(buffer)
	frame.RetirePriorTo, _, _ = ReadVarIntValue(buffer)
	frame.Length, _ = buffer.ReadByte()
	frame.ConnectionId = make([]byte, frame.Length, frame.Length)
	buffer.Read(frame.ConnectionId)
	binary.Read(buffer, binary.BigEndian, &frame.StatelessResetToken)
	return frame
}

type RetireConnectionId struct {
	SequenceNumber uint64
}

func (frame *RetireConnectionId) FrameType() FrameType { return RetireConnectionIdType }
func (frame *RetireConnectionId) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.SequenceNumber)
}
func (frame *RetireConnectionId) shouldBeRetransmitted() bool { return true }
func (frame *RetireConnectionId) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.SequenceNumber)) }
func ReadRetireConnectionId(buffer *bytes.Reader) *RetireConnectionId {
	frame := new(RetireConnectionId)
	buffer.ReadByte() // Discard frame byte
	frame.SequenceNumber, _, _ = ReadVarIntValue(buffer)
	return frame
}

type PathChallenge struct {
	Data [8]byte
}

func (frame *PathChallenge) FrameType() FrameType { return PathChallengeType }
func (frame *PathChallenge) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	buffer.Write(frame.Data[:])
}
func (frame *PathChallenge) shouldBeRetransmitted() bool { return true }
func (frame *PathChallenge) FrameLength() uint16         { return 1 + 8 }
func ReadPathChallenge(buffer *bytes.Reader) *PathChallenge {
	frame := new(PathChallenge)
	buffer.ReadByte() // Discard frame byte
	buffer.Read(frame.Data[:])
	return frame
}

type PathResponse struct {
	Data [8]byte
}

func (frame *PathResponse) FrameType() FrameType { return PathResponseType }
func (frame *PathResponse) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	buffer.Write(frame.Data[:])
}
func (frame *PathResponse) shouldBeRetransmitted() bool { return false }
func (frame *PathResponse) FrameLength() uint16         { return 1 + 8 }
func ReadPathResponse(buffer *bytes.Reader) *PathResponse {
	frame := new(PathResponse)
	buffer.ReadByte() // Discard frame byte
	buffer.Read(frame.Data[:])
	return frame
}
func NewPathResponse(data [8]byte) *PathResponse {
	frame := new(PathResponse)
	frame.Data = data
	return frame
}

type ConnectionCloseFrame struct {
	ErrorCode          uint64
	ErrorFrameType     uint64
	ReasonPhraseLength uint64
	ReasonPhrase       string
}

func (frame *ConnectionCloseFrame) FrameType() FrameType { return ConnectionCloseType }
func (frame *ConnectionCloseFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.ErrorCode)
	WriteVarInt(buffer, frame.ErrorFrameType)
	WriteVarInt(buffer, frame.ReasonPhraseLength)
	if frame.ReasonPhraseLength > 0 {
		buffer.Write([]byte(frame.ReasonPhrase))
	}
}
func (frame *ConnectionCloseFrame) shouldBeRetransmitted() bool { return false }
func (frame *ConnectionCloseFrame) FrameLength() uint16         { return 1 + uint16(VarIntLen(frame.ErrorCode)+VarIntLen(frame.ErrorFrameType)+VarIntLen(frame.ReasonPhraseLength)) + uint16(frame.ReasonPhraseLength) }
func NewConnectionCloseFrame(buffer *bytes.Reader) *ConnectionCloseFrame {
	frame := new(ConnectionCloseFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.ErrorCode, _, _ = ReadVarIntValue(buffer)
	frame.ErrorFrameType, _, _ = ReadVarIntValue(buffer)
	frame.ReasonPhraseLength, _, _ = ReadVarIntValue(buffer)
	if frame.ReasonPhraseLength > 0 {
		reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.ReasonPhrase = string(reasonBytes)
	}
	return frame
}

type ApplicationCloseFrame struct {
	// TODO: Merge it with 0x1c
	ErrorCode          uint64
	ReasonPhraseLength uint64
	ReasonPhrase       string
}

func (frame *ApplicationCloseFrame) FrameType() FrameType { return ApplicationCloseType }
func (frame *ApplicationCloseFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
	WriteVarInt(buffer, frame.ErrorCode)
	WriteVarInt(buffer, frame.ReasonPhraseLength)
	if frame.ReasonPhraseLength > 0 {
		buffer.Write([]byte(frame.ReasonPhrase))
	}
}
func (frame *ApplicationCloseFrame) shouldBeRetransmitted() bool { return false }
func (frame *ApplicationCloseFrame) FrameLength() uint16         { return 1 + 2 + uint16(VarIntLen(frame.ReasonPhraseLength)) + uint16(frame.ReasonPhraseLength) }
func NewApplicationCloseFrame(buffer *bytes.Reader) *ApplicationCloseFrame {
	frame := new(ApplicationCloseFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	frame.ErrorCode, _, _ = ReadVarIntValue(buffer)
	frame.ReasonPhraseLength, _, _ = ReadVarIntValue(buffer)
	if frame.ReasonPhraseLength > 0 {
		reasonBytes := make([]byte, frame.ReasonPhraseLength, frame.ReasonPhraseLength)
		binary.Read(buffer, binary.BigEndian, &reasonBytes)
		frame.ReasonPhrase = string(reasonBytes)
	}
	return frame
}

type HandshakeDoneFrame byte

func (frame *HandshakeDoneFrame) FrameType() FrameType { return HandshakeDoneType }
func (frame *HandshakeDoneFrame) WriteTo(buffer *bytes.Buffer) {
	WriteVarInt(buffer, uint64(frame.FrameType()))
}
func (frame *HandshakeDoneFrame) shouldBeRetransmitted() bool { return true }
func (frame *HandshakeDoneFrame) FrameLength() uint16         { return 1 }
func NewHandshakeDoneFrame(buffer *bytes.Reader) *HandshakeDoneFrame {
	frame := new(HandshakeDoneFrame)
	_, _ = ReadVarInt(buffer) // Discard frame type
	return frame
}
