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
	"crypto/cipher"
	"github.com/mpiraux/pigotls"
	. "github.com/mpiraux/master-thesis/lib"
)

var quicVersionSalt = []byte{  // See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.2
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
}

const (
	clientInitialLabel = "client in"
	serverInitialLabel = "server in"
)

type EncryptionLevel int

const (
	EncryptionLevelNone EncryptionLevel = iota
	EncryptionLevelInitial
	EncryptionLevel0RTT
	EncryptionLevelHandshake
	EncryptionLevel1RTT
	EncryptionLevelBest  // A special flag to indicate that the best encryption level available should be used
)

func (eL EncryptionLevel) String() string {
	return encryptionLevelToString[eL]
}

var encryptionLevelToString = map[EncryptionLevel]string {
	EncryptionLevelNone: "None",
	EncryptionLevelInitial: "Initial",
	EncryptionLevelHandshake: "Handshake",
	EncryptionLevel0RTT: "0RTT",
	EncryptionLevel1RTT: "1RTT",
	EncryptionLevelBest: "Best",
}

var packetTypeToEncryptionLevel = map[PacketType]EncryptionLevel{
	Initial: EncryptionLevelInitial,
	Retry: EncryptionLevelNone,
	Handshake: EncryptionLevelHandshake,
	ZeroRTTProtected: EncryptionLevel0RTT,
	ShortHeaderPacket: EncryptionLevel1RTT,
}

type DirectionalEncryptionLevel struct {
	EncryptionLevel
	Read bool
}

type CryptoState struct {
	Read  cipher.AEAD
	Write cipher.AEAD
	PacketRead *pigotls.Cipher
	PacketWrite *pigotls.Cipher
}

func (s *CryptoState) InitRead(tls *pigotls.Connection, readSecret []byte) {
	s.Read = newProtectedAead(tls, readSecret)
	s.PacketRead = tls.NewCipher(tls.HkdfExpandLabel(readSecret, "pn", nil, tls.AEADKeySize()))
}

func (s *CryptoState) InitWrite(tls *pigotls.Connection, writeSecret []byte) {
	s.Write = newProtectedAead(tls, writeSecret)
	s.PacketWrite = tls.NewCipher(tls.HkdfExpandLabel(writeSecret, "pn", nil, tls.AEADKeySize()))
}

func NewInitialPacketProtection(conn *Connection) *CryptoState {
	initialSecret := conn.Tls.HkdfExtract(quicVersionSalt, conn.DestinationCID)
	readSecret := conn.Tls.HkdfExpandLabel(initialSecret, serverInitialLabel, nil, conn.Tls.HashDigestSize())
	writeSecret := conn.Tls.HkdfExpandLabel(initialSecret, clientInitialLabel, nil, conn.Tls.HashDigestSize())
	return NewProtectedCryptoState(conn.Tls, readSecret, writeSecret)
}

func NewProtectedCryptoState(tls *pigotls.Connection, readSecret []byte, writeSecret []byte) *CryptoState {
	s := new(CryptoState)
	if len(readSecret) > 0 {
		s.InitRead(tls, readSecret)
	}
	if len(writeSecret) > 0 {
		s.InitWrite(tls, writeSecret)
	}
	return s
}

func newProtectedAead(tls *pigotls.Connection, secret []byte) cipher.AEAD {
	k := tls.HkdfExpandLabel(secret, "key", nil, tls.AEADKeySize())
	iv := tls.HkdfExpandLabel(secret, "iv", nil, tls.AEADIvSize())

	aead, err := NewWrappedAESGCM(k, iv)
	if err != nil {
		panic(err)
	}
	return aead
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
	if sampleOffset <= 0 || sampleOffset+sampleLength > len(packetBytes) {
		sampleOffset = 4
	}
	return packetBytes[sampleOffset:sampleOffset+sampleLength], sampleOffset
}
