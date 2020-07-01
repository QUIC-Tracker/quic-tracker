//
// QUIC-Tracker is a test suite for QUIC, built upon a minimal client implementation in Go.
// It is currently draft-27 and TLS-1.3 compatible.
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
// Copyright (C) 2017-2020  Maxime Piraux
//
package quictracker

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	. "github.com/QUIC-Tracker/quic-tracker/lib"
	_ "github.com/mpiraux/ls-qpack-go"
	"github.com/mpiraux/pigotls"
	"io"
	"math"
	"net"
	"time"
)

// TODO: Reconsider the use of global variables
var QuicVersion uint32 = 0xff00001d // See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-4
var QuicALPNToken = "hq-29"         // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html
var QuicH3ALPNToken = "h3-29"       // See https://tools.ietf.org/html/draft-ietf-quic-http-17#section-2.1

const (
	MinimumInitialLength       = 1252
	MinimumInitialLengthv6     = 1232
	MaxTheoreticUDPPayloadSize = 65507
	MaximumVersion             = 0xff00001c
	MinimumVersion             = 0xff00001c
)

// errors

const (
	ERR_STREAM_LIMIT_ERROR = 0x04
	ERR_STREAM_STATE_ERROR = 0x05
	ERR_PROTOCOL_VIOLATION = 0x0a
)

type PacketNumber uint64

func ReadPacketNumber (buffer *bytes.Reader) PacketNumber {
	v, _, _ := ReadVarIntValue(buffer)
	return PacketNumber(v)
}

func (p PacketNumber) Truncate(largestAcknowledged PacketNumber) TruncatedPN {
	if p < largestAcknowledged {
		panic("PNs should be truncated with a lower PN")
	}
	length := (int(math.Log2(float64(p - largestAcknowledged + 1))) / 8) + 1  // See: https://tools.ietf.org/html/draft-ietf-quic-transport-13#section-4.8
	if length > 4 {
		println("couldn't truncate", p, "with", largestAcknowledged)
		panic(length)
	}
	return TruncatedPN{uint32(p) & (0xFFFFFFFF >> (8 * (4 - uint(length)))), length}
}

type TruncatedPN struct {
	Value uint32
	Length int
}

func ReadTruncatedPN(buffer *bytes.Reader, length int) TruncatedPN {
	pn := TruncatedPN{Length: length}
	value := make([]byte, 4, 4)
	buffer.Read(value[4-length:])
	pn.Value = binary.BigEndian.Uint32(value)
	return pn
}

func (t TruncatedPN) Encode() []byte {
	buffer := new(bytes.Buffer)
	switch t.Length {
	case 1:
		buffer.WriteByte(byte(t.Value))
	case 2:
		buffer.Write(Uint16ToBEBytes(uint16(t.Value)))
	case 3:
		buffer.Write(Uint24ToBEBytes(t.Value))
	case 4:
		buffer.Write(Uint32ToBEBytes(t.Value))
	}
	return buffer.Bytes()
}

func (t TruncatedPN) Join(p PacketNumber) PacketNumber {
	return PacketNumber(uint64(p & (0xFFFFFFFFFFFFFFFF << uint(t.Length * 8))) | uint64(t.Value))
}

func (t *TruncatedPN) SetLength(length int) {
	t.Length = length
}

type VarInt struct {
	Value uint64
	Length int
}
func NewVarInt(value uint64) VarInt {
	return VarInt{value, VarIntLen(value)}
}
func ReadVarInt(buffer io.ByteReader) (VarInt, error) {
	i, l, err := ReadVarIntValue(buffer)
	if err != nil {
		return VarInt{}, err
	}
	return VarInt{Value: i, Length: l}, nil
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

var PNSpaceToPacketType = map[PNSpace]PacketType{
	PNSpaceInitial: Initial,
	PNSpaceHandshake: Handshake,
	PNSpaceAppData: ShortHeaderPacket, // TODO: Deal with O-RTT packets
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

func Uint24ToBEBytes(uint32 uint32) []byte {
	b := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(b, uint32)
	return b[1:]
}

func Uint16ToBEBytes(uint16 uint16) []byte {
	b := make([]byte, 2, 2)
	binary.BigEndian.PutUint16(b, uint16)
	return b
}

func Max(a, b int) int { if a < b { return b }; return a}
func Min(a, b int) int { if a > b { return b }; return a}

type PacketNumberQueue []PacketNumber
func (a PacketNumberQueue) Less(i, j int) bool { return a[i] > a[j] }
func (a PacketNumberQueue) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a PacketNumberQueue) Len() int           { return len(a) }

type ConnectionID []byte

func (c ConnectionID) CIDL() uint8 {
	return uint8(len(c))
}

func (c ConnectionID) WriteTo(buffer *bytes.Buffer) {
	buffer.WriteByte(c.CIDL())
	buffer.Write(c)
}

func (c ConnectionID) String() string {
	return hex.EncodeToString(c)
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

type ECNStatus int

const (
	ECNStatusNonECT ECNStatus = 0
	ECNStatusECT_1            = 1
	ECNStatusECT_0            = 2
	ECNStatusCE               = 3
)

type PacketContext struct {
	Timestamp  time.Time
	RemoteAddr net.Addr
	ECNStatus
	DatagramSize uint16
	PacketSize uint16
	WasBuffered bool
}

type IncomingPayload struct {
	PacketContext
	Payload []byte
}

type UnprocessedPayload struct {
	IncomingPayload
	EncryptionLevel
}

type QueuedFrame struct {
	Frame
	EncryptionLevel
}

type PacketAcknowledged struct {
	PacketNumber
	PNSpace
}

type PacketToSend struct {
	Packet
	EncryptionLevel
}