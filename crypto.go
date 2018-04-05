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
	"bytes"
	"encoding/binary"
	"github.com/mpiraux/pigotls"
)

var quicVersionSalt = []byte {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.2
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
}

const (
	clientHSecretLabel = "client hs"
	serverHSecretLabel = "server hs"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.3
	clientPpSecret0Label = "EXPORTER-QUIC client 1rtt"
	serverPpSecret0Label = "EXPORTER-QUIC server 1rtt"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-10#section-5.2.4
	client0rttSecretLabel = "EXPORTER-QUIC 0rtt"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.6
	packetNumberLabel = "EXPORTER-QUIC packet number"
)

type CryptoState struct {
	Read  cipher.AEAD
	Write cipher.AEAD
}
func NewCleartextSaltedCryptoState(conn *Connection) *CryptoState {
	s := new(CryptoState)
	handshakeSecret := saltSecret(conn.Tls, EncodeArgs(conn.ConnectionId))
	s.Read = newProtectedAead(conn.Tls, qhkdfExpand(conn.Tls, handshakeSecret, serverHSecretLabel, conn.Tls.HashDigestSize()))
	s.Write = newProtectedAead(conn.Tls, qhkdfExpand(conn.Tls, handshakeSecret, clientHSecretLabel, conn.Tls.HashDigestSize()))
	return s
}
func NewProtectedCryptoState(tls *pigotls.Connection) *CryptoState {
	s := new(CryptoState)
	readSecret, err := tls.ExportSecret(serverPpSecret0Label, []byte{}, false)
	if err != nil {
		panic(err)
	}
	s.Read = newProtectedAead(tls, readSecret)
	writeSecret, err := tls.ExportSecret(clientPpSecret0Label, []byte{}, false)
	if err != nil {
		panic(err)
	}
	s.Write = newProtectedAead(tls, writeSecret)
	return s
}
func NewZeroRTTProtectedCryptoState(tls *pigotls.Connection) *CryptoState {
	s := new(CryptoState)
	writeSecret, err := tls.ExportSecret(client0rttSecretLabel, []byte{}, true)
	if err != nil {
		panic(err)
	}
	s.Write = newProtectedAead(tls, writeSecret)
	return s
}

func newProtectedAead(tls *pigotls.Connection, secret []byte) cipher.AEAD {
	k := qhkdfExpand(tls, secret, "key", tls.AEADKeySize())
	iv := qhkdfExpand(tls, secret, "iv", tls.AEADIvSize())

	aead, err := newWrappedAESGCM(k, iv)
	if err != nil {
		panic(err)
	}
	return aead
}
func saltSecret(tls *pigotls.Connection, secret []byte) []byte {
	return tls.HkdfExtract(quicVersionSalt, secret)
}
func qhkdfExpand(tls *pigotls.Connection, secret []byte, label string, length int) []byte {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.2.3
	label = "QUIC " + label
	info := string(length >> 8) + string(byte(length)) + string(len(label)) + label
	return tls.HkdfExpand(secret, bytes.NewBufferString(info).Bytes(), length)
}
func GetPacketGap(conn *Connection) uint32 {
	packetNumberSecret, err := conn.Tls.ExportSecret(packetNumberLabel, []byte{}, false)
	if err != nil {
		panic(err)
	}

	sequence := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(sequence, uint32(conn.PacketNumber))

	gapBytes := conn.Tls.HkdfExpandLabel(packetNumberSecret, "packet sequence gap", sequence, 4)
	return binary.BigEndian.Uint32(gapBytes)
}