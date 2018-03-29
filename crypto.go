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
	"github.com/bifurcation/mint"
	"bytes"
	"crypto"
	"encoding/binary"
)

var quicVersionSalt = []byte {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.2.1
	0x9c, 0x10, 0x8f, 0x98, 0x52, 0x0a, 0x5c, 0x5c,
	0x32, 0x96, 0x8e, 0x95, 0x0e, 0x8a, 0x2c, 0x5f,
	0xe0, 0x6d, 0x6c, 0x38,
}

const (
	clientHSecretLabel = "client hs"
	serverHSecretLabel = "server hs"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.2.3
	clientPpSecret0Label = "EXPORTER-QUIC client 1rtt"
	serverPpSecret0Label = "EXPORTER-QUIC server 1rtt"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.6
	packetNumberLabel = "EXPORTER-QUIC packet number"
)

type CryptoState struct {
	Read  cipher.AEAD
	Write cipher.AEAD
}
func NewCleartextCryptoState() *CryptoState {
	s := new(CryptoState)
	s.Read = &aeadFNV{}
	s.Write = &aeadFNV{}
	return s
}
func NewCleartextSaltedCryptoState(conn *Connection, cipherSuite *mint.CipherSuiteParams) *CryptoState {
	s := new(CryptoState)
	handshakeSecret := saltSecret(EncodeArgs(conn.ConnectionId), cipherSuite.Hash)
	s.Read = newProtectedAead(qhkdfExpand(cipherSuite.Hash, handshakeSecret, serverHSecretLabel, cipherSuite.Hash.Size()), cipherSuite)
	s.Write = newProtectedAead(qhkdfExpand(cipherSuite.Hash, handshakeSecret, clientHSecretLabel, cipherSuite.Hash.Size()), cipherSuite)
	return s
}
func NewProtectedCryptoState(conn *Connection) *CryptoState {
	s := new(CryptoState)
	readSecret, err := conn.tls.ComputeExporter(serverPpSecret0Label, []byte{}, conn.cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}
	s.Read = newProtectedAead(readSecret, conn.cipherSuite)
	writeSecret, err := conn.tls.ComputeExporter(clientPpSecret0Label, []byte{}, conn.cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}
	s.Write = newProtectedAead(writeSecret, conn.cipherSuite)
	return s
}

func newProtectedAead(secret []byte, cipherSuite *mint.CipherSuiteParams) cipher.AEAD {
	k := qhkdfExpand(cipherSuite.Hash, secret, "key", cipherSuite.KeyLen)
	iv := qhkdfExpand(cipherSuite.Hash, secret, "iv", cipherSuite.IvLen)

	aead, err := newWrappedAESGCM(k, iv)
	if err != nil {
		panic(err)
	}
	return aead
}
func saltSecret(secret []byte, hash crypto.Hash) []byte {
	return mint.HkdfExtract(hash, quicVersionSalt, secret)
}
func qhkdfExpand(hash crypto.Hash, secret []byte, label string, length int) []byte {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.2.3
	label = "QUIC " + label
	info := string(length >> 8) + string(byte(length)) + string(len(label)) + label
	return mint.HkdfExpand(hash, secret, bytes.NewBufferString(info).Bytes(), length)
}
func GetPacketGap(conn *Connection) uint32 {
	packetNumberSecret, err := conn.tls.ComputeExporter(packetNumberLabel, []byte{}, conn.cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}

	sequence := make([]byte, 4, 4)
	binary.BigEndian.PutUint32(sequence, uint32(conn.PacketNumber))

	gapBytes := mint.HkdfExpandLabel(conn.cipherSuite.Hash, packetNumberSecret, "QUIC packet sequence gap", sequence, 4)
	return binary.BigEndian.Uint32(gapBytes)
}