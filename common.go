/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package masterthesis

import (
	"encoding/binary"
	"github.com/mpiraux/pigotls"
)

var QuicVersion uint32 = 0xff00000d // See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-4
var QuicALPNToken = "hq-13"         // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html

const (
	MinimumInitialLength   = 1252
	MinimumInitialLengthv6 = 1232
	MaxUDPPayloadSize      = 65507
	MaximumVersion         = 0xff00000d
	MinimumVersion         = 0xff00000c
)

// errors

const (
	ERR_PROTOCOL_VIOLATION = 0xA
)

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

type PacketNumberQueue []uint64
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

func GetPacketSample(header Header, packetBytes []byte) ([]byte, int) {
	var sampleOffset int
	sampleLength := 16
	switch h := header.(type) {
	case *LongHeader:
		sampleOffset = h.LengthBeforePN + 4
	case *ShortHeader:
		sampleOffset = 1 + len(h.DestinationCID) + 4

		if sampleOffset + sampleLength > len(packetBytes) {
			sampleOffset = len(packetBytes) - sampleLength
		}
	}
	return packetBytes[sampleOffset:sampleOffset+sampleLength], sampleOffset
}