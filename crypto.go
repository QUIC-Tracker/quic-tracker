package masterthesis

import (
	"crypto/cipher"
	"github.com/bifurcation/mint"
	"encoding/hex"
	"bytes"
	"crypto"
)

const (
	// See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.2.1
	quicVersionSalt    = "afc824ec5fc77eca1e9d36f37fb2d46518c36639"
	clientHSecretLabel = "client hs"
	serverHSecretLabel = "server hs"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.2.3
	clientPpSecret0Label = "EXPORTER-QUIC client 1rtt"
	serverPpSecret0Label = "EXPORTER-QUIC server 1rtt"
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
	salt, err := hex.DecodeString(quicVersionSalt)
	if err != nil {
		panic(err)
	}
	return mint.HkdfExtract(hash, salt, secret)
}
func qhkdfExpand(hash crypto.Hash, secret []byte, label string, length int) []byte {  // See https://tools.ietf.org/html/draft-ietf-quic-tls-09#section-5.2.3
	label = "QUIC " + label
	info := string(length >> 8) + string(byte(length)) + string(len(label)) + label + string(0x00)
	return mint.HkdfExpand(hash, secret, bytes.NewBufferString(info).Bytes(), length)
}