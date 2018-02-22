package masterthesis

import (
	"encoding/binary"
)

var QuicVersion uint32 = 0xff000008 // See https://tools.ietf.org/html/draft-ietf-quic-transport-08#section-4
var QuicALPNToken = "hq-08"         // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html

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