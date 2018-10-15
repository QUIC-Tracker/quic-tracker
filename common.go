//
// QUIC-Tracker is a test suite for QUIC, built upon a minimal client implementation in Go.
// It is currently draft-13 and TLS-1.3-draft-28 compatible.
//
// The main package is a toolbox to parse and create QUIC packets of all types. More high-level client behaviours are
// implemented in the package agents. Several test scenarii are implemented in the package scenarii.
//
// Architecture
//
// QUIC-Tracker is comprised of three parts.
//
// The first is this package, which contains types, methods and functions to
// parse and create QUIC packets that can be easily manipulated.
//
// The second is the package agents, which implements all the features and behaviours of a QUIC client as asynchronous
// message-passing objects. These agents exchange messages through the broadcasting channels defined in the Connection
// struct. This allows additional behaviours to be hooked up and respond to several events that occur when the
// connection is active.
//
// The third the package scenarii, which contains all the tests of the test suite. They can be ran using the scripts in
// the package bin/test_suite. The tests results are produced in an unified JSON format. It is described in the Trace
// type documentation.
//
// License and copyright
//
// QUIC-Tracker is licensed under the GNU Affero General Public License version 3. You can find its terms in the
// LICENSE file, or at https://www.gnu.org/licenses/agpl.txt.
//
// Copyright (C) 2017-2018  Maxime Piraux
//
package quictracker

import (
	"encoding/binary"
	"github.com/mpiraux/pigotls"
	"math"
	"bytes"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
)

var QuicVersion uint32 = 0xff00000f // See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-4
var QuicALPNToken = "hq-15"         // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html

const (
	MinimumInitialLength   = 1252
	MinimumInitialLengthv6 = 1232
	MaxUDPPayloadSize      = 65507
	MaximumVersion         = 0xff00000f
	MinimumVersion         = 0xff00000f
)

// errors

const (
	ERR_STREAM_ID_ERROR = 0x4
	ERR_PROTOCOL_VIOLATION = 0xA
)

type PacketNumber uint64

func ReadPacketNumber (buffer *bytes.Reader) PacketNumber {
	v, _ := ReadVarIntValue(buffer)
	return PacketNumber(v)
}

func (p PacketNumber) Truncate(largestAcknowledged PacketNumber) TruncatedPN {
	if p < largestAcknowledged {
		panic("PNs should be truncated with a lower PN")
	}
	length := (int(math.Log2(float64(p - largestAcknowledged + 1))) / 8) + 1  // See: https://tools.ietf.org/html/draft-ietf-quic-transport-13#section-4.8
	switch length {
	case 1:
		mask := uint32(0x7f)
		return TruncatedPN{uint32(p) & mask, 1}
	case 2:
		mask := uint32(0x3fff)
		return TruncatedPN{(uint32(p) & mask) | 0x8000, 1}
	case 3, 4:
		mask := uint32(0x3fffffff)
		return TruncatedPN{(uint32(p) & mask) | 0xc0000000, 4}
	default:
		println("couldn't truncate", p, "with", largestAcknowledged)
		panic(length)
	}
}

type TruncatedPN struct {
	Value uint32
	Length int
}

func ReadTruncatedPN(buffer *bytes.Reader) TruncatedPN {
	firstByte, _ := buffer.ReadByte()
	if firstByte & 0x80 == 0 {
		return TruncatedPN{uint32(firstByte), 1}
	} else if firstByte & 0xc0 == 0x80 {
		twoBytes := make([]byte, 2)
		buffer.UnreadByte()
		buffer.Read(twoBytes)
		return TruncatedPN{uint32(0x3fff & binary.BigEndian.Uint16(twoBytes)), 2}
	} else if firstByte & 0xc0 == 0xc0 {
		fourBytes := make([]byte, 4)
		buffer.UnreadByte()
		buffer.Read(fourBytes)
		return TruncatedPN{uint32(0x3fffffff & binary.BigEndian.Uint32(fourBytes)), 4}
	} else {
		panic("Could not decode truncated packet number")
	}
}

func (t TruncatedPN) Encode() []byte {
	buffer := new(bytes.Buffer)
	switch t.Length {
	case 1:
		buffer.WriteByte(byte(t.Value))
	case 2:
		buffer.Write(Uint16ToBEBytes(uint16(t.Value)))
	case 4:
		buffer.Write(Uint32ToBEBytes(t.Value))
	}
	return buffer.Bytes()
}

func (t TruncatedPN) Join(p PacketNumber) PacketNumber {
	var mask uint64
	switch t.Length {
	case 1:
		mask = uint64(0x7f)
	case 2:
		mask = uint64(0x3fff)
	case 4:
		mask = uint64(0x3fffffff)
	}
	return PacketNumber((uint64(p) & ^mask) | (uint64(t.Value) & mask))
}

type VarInt struct {
	Value uint64
	Length int
}
func NewVarInt(value uint64) VarInt {
	return VarInt{value, VarIntLen(value)}
}
func ReadVarInt(buffer *bytes.Reader) (VarInt, error) {
	v := VarInt{Length: buffer.Len()}
	i, err := ReadVarIntValue(buffer)
	if err != nil {
		return VarInt{}, err
	}
	v.Length -= buffer.Len()
	v.Value = i
	return v, nil
}

func (v VarInt) Encode() []byte {
	buffer := new(bytes.Buffer)
	WriteVarInt(buffer, v.Value)
	return buffer.Bytes()
}

type PNSpace int

const (
	PNSpaceInitial PNSpace = iota
	PNSpaceHandshake
	PNSpaceAppData
	PNSpaceNoSpace
)

var PNSpaceToString = map[PNSpace]string{
	PNSpaceInitial: "Initial",
	PNSpaceHandshake: "Handshake",
	PNSpaceAppData: "Application data",
}

var PNSpaceToEpoch = map[PNSpace]pigotls.Epoch{
	PNSpaceInitial: pigotls.EpochInitial,
	PNSpaceHandshake: pigotls.EpochHandshake,
	PNSpaceAppData: pigotls.Epoch1RTT,
}

var EpochToPNSpace = map[pigotls.Epoch]PNSpace {
	pigotls.EpochInitial: PNSpaceInitial,
	pigotls.EpochHandshake: PNSpaceHandshake,
	pigotls.Epoch0RTT: PNSpaceAppData,
	pigotls.Epoch1RTT: PNSpaceAppData,
}

func (pns PNSpace) String() string {
	return PNSpaceToString[pns]
}

func (pns PNSpace) Epoch() pigotls.Epoch {
	return PNSpaceToEpoch[pns]
}

func Uint32ToBEBytes(uint32 uint32) []byte {
	b := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(b, uint32)
	return b
}

func Uint16ToBEBytes(uint16 uint16) []byte {
	b := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(b, uint16)
	return b
}

func Max(a, b int) int { if a < b { return b }; return a}

type PacketNumberQueue []PacketNumber
func (a PacketNumberQueue) Less(i, j int) bool { return a[i] > a[j] }
func (a PacketNumberQueue) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a PacketNumberQueue) Len() int           { return len(a) }

type ConnectionID []byte

func (c ConnectionID) CIDL() uint8 {
	if len(c) == 0 {
		return 0
	}
	return uint8(len(c) - 3)
}

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

type UnprocessedPayload struct {
	EncryptionLevel
	Payload []byte
}

type QueuedFrame struct {
	Frame
	EncryptionLevel
}