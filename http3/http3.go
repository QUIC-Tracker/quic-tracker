package http3

import (
	"bytes"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/lib"
	"io"
)

const (
	StreamTypeControl = 0x00
	StreamTypePush    = 0x01
)

const (
	FrameTypeDATA         = 0x0
	FrameTypeHEADERS      = 0x1
	FrameTypePRIORITY     = 0x2
	FrameTypeCANCEL_PUSH  = 0x3
	FrameTypeSETTINGS     = 0x4
	FrameTypePUSH_PROMISE = 0x5
	FrameTypeGOAWAY       = 0x7
	FrameTypeMAX_PUSH_ID  = 0xd
)

func ReadHTTPFrame(buffer *bytes.Reader) HTTPFrame {
	typeByte, _ := ReadVarInt(buffer)
	_, _ = buffer.Seek(-int64(typeByte.Length), io.SeekCurrent)
	switch typeByte.Value {
	case FrameTypeDATA:
		return ReadDATA(buffer)
	case FrameTypeHEADERS:
		return ReadHEADERS(buffer)
	case FrameTypePRIORITY:
		return ReadPRIORITY(buffer)
	case FrameTypeCANCEL_PUSH:
		return ReadCANCEL_PUSH(buffer)
	case FrameTypeSETTINGS:
		return ReadSETTINGS(buffer)
	case FrameTypePUSH_PROMISE:
		return ReadPUSH_PROMISE(buffer)
	case FrameTypeGOAWAY:
		return ReadGOAWAY(buffer)
	case FrameTypeMAX_PUSH_ID:
		return ReadMAX_PUSH_ID(buffer)
	default:
		return ReadUnknownFrame(buffer)
	}
}

type HTTPFrame interface {
	FrameType() uint64
	Name() string
	WriteTo(buffer *bytes.Buffer)
	WireLength() uint64
}

type HTTPFrameHeader struct {
	Type   VarInt
	Length VarInt
}

func (h *HTTPFrameHeader) FrameType() uint64 {
	return h.Type.Value
}
func (h *HTTPFrameHeader) WriteTo(buffer *bytes.Buffer) {
	buffer.Write(h.Type.Encode())
	buffer.Write(h.Length.Encode())
}
func (h *HTTPFrameHeader) WireLength() uint64 {
	return uint64(h.Length.Length + h.Type.Length) + h.Length.Value
}

func ReadHTTPFrameHeader(buffer *bytes.Reader) HTTPFrameHeader {
	f := HTTPFrameHeader{}
	f.Type, _ = ReadVarInt(buffer)
	f.Length, _ = ReadVarInt(buffer)
	return f
}

type DATA struct {
	HTTPFrameHeader
	Payload []byte
}

func (f *DATA) Name() string { return "DATA" }
func (f *DATA) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.Payload)
}
func ReadDATA(buffer *bytes.Reader) *DATA {
	f := DATA{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.Payload = make([]byte, f.Length.Value)
	buffer.Read(f.Payload)
	return &f
}
func NewDATA(payload []byte) *DATA {
	return &DATA{HTTPFrameHeader{NewVarInt(FrameTypeDATA), NewVarInt(uint64(len(payload)))}, payload}
}

type HEADERS struct {
	HTTPFrameHeader
	HeaderBlock []byte
}

func (f *HEADERS) Name() string { return "HEADERS" }
func (f *HEADERS) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.HeaderBlock)
}
func ReadHEADERS(buffer *bytes.Reader) *HEADERS {
	f := HEADERS{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.HeaderBlock = make([]byte, f.Length.Value)
	buffer.Read(f.HeaderBlock)
	return &f
}
func NewHEADERS(headerBlock []byte) *HEADERS {
	return &HEADERS{HTTPFrameHeader{NewVarInt(FrameTypeHEADERS), NewVarInt(uint64(len(headerBlock)))}, headerBlock}
}

const (
	ElementTypeRequestStream = 0x00
	ElementTypePushStream    = 0x01
	ElementTypePlaceholder   = 0x10
	ElementTypeRootOfTheTree = 0x11
)

type PRIORITY struct {
	HTTPFrameHeader
	PrioritizedType      uint8
	DependencyType       uint8
	Empty                uint8
	Exclusive            bool
	PrioritizedElementID VarInt
	ElementDependencyID  VarInt
	Weight               uint8
}

func (f *PRIORITY) Name() string { return "PRIORITY" }
func (f *PRIORITY) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	firstByte := (f.PrioritizedType << 6) | (f.DependencyType << 4) | (f.Empty << 1)
	if f.Exclusive {
		firstByte |= 0x1
	}
	buffer.WriteByte(firstByte)
	buffer.Write(f.PrioritizedElementID.Encode())
	buffer.Write(f.ElementDependencyID.Encode())
	buffer.WriteByte(f.Weight)
}
func ReadPRIORITY(buffer *bytes.Reader) *PRIORITY {
	f := PRIORITY{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	firstByte, _ := buffer.ReadByte()
	f.PrioritizedType = (firstByte & 0xc0) >> 6
	f.DependencyType = (firstByte & 0x30) >> 4
	f.Empty = (firstByte & 0xe) >> 1
	f.Exclusive = (firstByte & 0x1) == 0x1
	f.PrioritizedElementID, _ = ReadVarInt(buffer)
	f.ElementDependencyID, _ = ReadVarInt(buffer)
	f.Weight, _ = buffer.ReadByte()
	return &f
}
func NewPRIORITY(prioritizedType uint8,
	dependencyType uint8,
	exclusive bool,
	prioritizedElementID uint64,
	elementDependencyID uint64,
	weight uint8,
) *PRIORITY {
	return &PRIORITY{
		HTTPFrameHeader{NewVarInt(FrameTypePRIORITY), NewVarInt(uint64(1 + lib.VarIntLen(prioritizedElementID) + lib.VarIntLen(elementDependencyID) + 1))},
		prioritizedType,
		dependencyType,
		0,
		exclusive,
		NewVarInt(prioritizedElementID),
		NewVarInt(elementDependencyID),
		weight,
	}
}

type CANCEL_PUSH struct {
	HTTPFrameHeader
	PushID VarInt
}

func (f *CANCEL_PUSH) Name() string { return "CANCEL_PUSH" }
func (f *CANCEL_PUSH) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.PushID.Encode())
}
func ReadCANCEL_PUSH(buffer *bytes.Reader) *CANCEL_PUSH {
	f := CANCEL_PUSH{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.PushID, _ = ReadVarInt(buffer)
	return &f
}
func NewCANCEL_PUSH(pushID uint64) *CANCEL_PUSH {
	return &CANCEL_PUSH{
		HTTPFrameHeader{NewVarInt(FrameTypeCANCEL_PUSH), NewVarInt(uint64(lib.VarIntLen(pushID)))},
		NewVarInt(pushID),
	}
}

type Setting struct {
	Identifier VarInt
	Value      VarInt
}

func (s Setting) WriteTo(buffer *bytes.Buffer) {
	buffer.Write(s.Identifier.Encode())
	buffer.Write(s.Value.Encode())
}
func ReadSetting(buffer *bytes.Reader) Setting {
	s := Setting{}
	s.Identifier, _ = ReadVarInt(buffer)
	s.Value, _ = ReadVarInt(buffer)
	return s
}

const (
	SETTINGS_HEADER_TABLE_SIZE     = 0x01
	SETTINGS_MAX_HEADER_LIST_SIZE  = 0x06
	SETTINGS_QPACK_BLOCKED_STREAMS = 0x07
	SETTINGS_NUM_PLACEHOLDERS      = 0x09
)

type SETTINGS struct {
	HTTPFrameHeader
	Settings []Setting
}

func (f *SETTINGS) Name() string { return "SETTINGS" }
func (f *SETTINGS) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	for _, s := range f.Settings {
		s.WriteTo(buffer)
	}
}
func ReadSETTINGS(buffer *bytes.Reader) *SETTINGS {
	f := SETTINGS{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	settingsBuffer := make([]byte, f.Length.Value)
	buffer.Read(settingsBuffer)
	settingsReader := bytes.NewReader(settingsBuffer)
	for settingsReader.Len() > 0 {
		f.Settings = append(f.Settings, ReadSetting(settingsReader))
	}
	return &f
}
func NewSETTINGS(settings []Setting) *SETTINGS {
	length := 0
	for _, s := range settings {
		length += s.Value.Length + 2
	}
	return &SETTINGS{
		HTTPFrameHeader{NewVarInt(FrameTypeSETTINGS), NewVarInt(uint64(length))},
		settings,
	}
}

type PUSH_PROMISE struct {
	HTTPFrameHeader
	PushID      VarInt
	HeaderBlock []byte
}

func (f *PUSH_PROMISE) Name() string { return "PUSH_PROMISE" }
func (f *PUSH_PROMISE) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.PushID.Encode())
	buffer.Write(f.HeaderBlock)
}
func ReadPUSH_PROMISE(buffer *bytes.Reader) *PUSH_PROMISE {
	f := PUSH_PROMISE{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.PushID, _ = ReadVarInt(buffer)
	f.HeaderBlock = make([]byte, int(f.Length.Value)-f.PushID.Length)
	return &f
}
func NewPUSH_PROMISE(pushID uint64, headerBlock []byte) *PUSH_PROMISE {
	return &PUSH_PROMISE{
		HTTPFrameHeader{NewVarInt(FrameTypePUSH_PROMISE), NewVarInt(uint64(lib.VarIntLen(pushID) + len(headerBlock)))},
		NewVarInt(pushID),
		headerBlock,
	}
}

type GOAWAY struct {
	HTTPFrameHeader
	StreamID VarInt
}

func (f *GOAWAY) Name() string { return "GOAWAY" }
func (f *GOAWAY) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.StreamID.Encode())
}
func ReadGOAWAY(buffer *bytes.Reader) *GOAWAY {
	f := GOAWAY{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.StreamID, _ = ReadVarInt(buffer)
	return &f
}
func NewGOAWAY(streamID uint64) *GOAWAY {
	return &GOAWAY{
		HTTPFrameHeader{NewVarInt(FrameTypeGOAWAY), NewVarInt(uint64(lib.VarIntLen(streamID)))},
		NewVarInt(streamID),
	}
}

type MAX_PUSH_ID struct {
	HTTPFrameHeader
	PushID VarInt
}

func (f *MAX_PUSH_ID) Name() string { return "MAX_PUSH_ID" }
func (f *MAX_PUSH_ID) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.PushID.Encode())
}
func ReadMAX_PUSH_ID(buffer *bytes.Reader) *MAX_PUSH_ID {
	f := MAX_PUSH_ID{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.PushID, _ = ReadVarInt(buffer)
	return &f
}
func NewMAX_PUSH_ID(pushID uint64) *MAX_PUSH_ID {
	return &MAX_PUSH_ID{
		HTTPFrameHeader{NewVarInt(FrameTypeMAX_PUSH_ID), NewVarInt(uint64(lib.VarIntLen(pushID)))},
		NewVarInt(pushID),
	}
}

type UnknownFrame struct {
	HTTPFrameHeader
	OpaquePayload []byte
}

func (f *UnknownFrame) Name() string { return fmt.Sprintf("Unknown (type=%d)", f.Type) }
func (f *UnknownFrame) WriteTo(buffer *bytes.Buffer) {
	f.HTTPFrameHeader.WriteTo(buffer)
	buffer.Write(f.OpaquePayload)
}
func ReadUnknownFrame(buffer *bytes.Reader) *UnknownFrame {
	f := UnknownFrame{HTTPFrameHeader: ReadHTTPFrameHeader(buffer)}
	f.OpaquePayload = make([]byte, f.Length.Value)
	buffer.Read(f.OpaquePayload)
	return &f
}
