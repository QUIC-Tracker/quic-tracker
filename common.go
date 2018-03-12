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
)

var QuicVersion uint32 = 0xff000009 // See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-4
var QuicALPNToken = "hq-09"         // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html

const (
	MinimumInitialLength   = 1252
	MinimumInitialLengthv6 = 1232
	LongHeaderSize         = 17
	MaxUDPPayloadSize      = 65507
	MinimumVersion         = 0xff000009
	MaximumVersion         = 0xff000009
)

func reverse(s []uint64) []uint64 {
	rev := make([]uint64, 0, len(s))
	last := len(s) - 1
	for i := 0; i < len(s); i++ {
		rev = append(rev, s[last-i])
	}
	return rev
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