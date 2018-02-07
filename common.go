package masterthesis

import (
	"encoding/binary"
)

var QuicVersion uint32 = 0xff000005       // See https://tools.ietf.org/html/draft-ietf-quic-transport-05#section-4
var QuicALPNToken = "hq-05"        // See https://www.ietf.org/mail-archive/web/quic/current/msg01882.html
const MinimumInitialLength = 1252 // TODO IPv6 is 1232 and should be supported as well
const LongHeaderSize = 17
const MaxUDPPayloadSize = 65507

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