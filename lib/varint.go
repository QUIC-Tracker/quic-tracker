package lib

/*This file has been adapted from https://github.com/lucas-clemente/quic-go and
is subject to following license and copyright.

-------------------------------------------------------------------------------

MIT License

Copyright (c) 2016 the quic-go authors & Google, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

import (
	"bytes"
	"fmt"
	"io"
)

// taken from the QUIC draft
const (
	maxVarInt1 = 63
	maxVarInt2 = 16383
	maxVarInt4 = 1073741823
	maxVarInt8 = 4611686018427387903
)

// ReadVarIntValue reads a number in the QUIC varint format
func ReadVarIntValue(b io.ByteReader) (uint64, int, error) {
	firstByte, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	// the first two bits of the first byte encode the length
	len := 1 << ((firstByte & 0xc0) >> 6)
	b1 := firstByte & (0xff - 0xc0)
	if len == 1 {
		return uint64(b1), 1, nil
	}
	b2, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if len == 2 {
		return uint64(b2) + uint64(b1)<<8, 2, nil
	}
	b3, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	b4, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if len == 4 {
		return uint64(b4) + uint64(b3)<<8 + uint64(b2)<<16 + uint64(b1)<<24, 4, nil
	}
	b5, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	b6, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	b7, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	b8, err := b.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	return uint64(b8) + uint64(b7)<<8 + uint64(b6)<<16 + uint64(b5)<<24 + uint64(b4)<<32 + uint64(b3)<<40 + uint64(b2)<<48 + uint64(b1)<<56, 8, nil
}

// WriteVarInt writes a number in the QUIC varint format
func WriteVarInt(b *bytes.Buffer, i uint64) {
	b.Write(EncodeVarInt(i))
}

func EncodeVarInt(i uint64) []byte {
	if i <= maxVarInt1 {
		return []byte{uint8(i)}
	} else if i <= maxVarInt2 {
		return []byte{uint8(i>>8) | 0x40, uint8(i)}
	} else if i <= maxVarInt4 {
		return []byte{uint8(i>>24) | 0x80, uint8(i >> 16), uint8(i >> 8), uint8(i)}
	} else if i <= maxVarInt8 {
		return []byte{
			uint8(i>>56) | 0xc0, uint8(i >> 48), uint8(i >> 40), uint8(i >> 32),
			uint8(i >> 24), uint8(i >> 16), uint8(i >> 8), uint8(i),
		}
	} else {
		panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
	}
}

// VarIntLen determines the number of bytes that will be needed to write a number
func VarIntLen(i uint64) int {
	if i <= maxVarInt1 {
		return 1
	}
	if i <= maxVarInt2 {
		return 2
	}
	if i <= maxVarInt4 {
		return 4
	}
	if i <= maxVarInt8 {
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}