package masterthesis

import (
	"crypto/cipher"
	"github.com/bifurcation/mint"
	"encoding/hex"
)

const (
	// See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.2.1
	quicVersionSalt = "afc824ec5fc77eca1e9d36f37fb2d46518c36639"
	clientCtSecretLabel = "QUIC client cleartext Secret"
	serverCtSecretLabel = "QUIC server cleartext Secret"

	// See https://tools.ietf.org/html/draft-ietf-quic-tls-07#section-5.2.3
	clientPpSecret0Label = "EXPORTER-QUIC client 1-RTT Secret"
	serverPpSecret0Label = "EXPORTER-QUIC server 1-RTT Secret"
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
	s.Read = newProtectedAead(saltSecret(EncodeArgs(conn.connectionId), serverCtSecretLabel, cipherSuite), cipherSuite)
	s.Write = newProtectedAead(saltSecret(EncodeArgs(conn.connectionId), clientCtSecretLabel, cipherSuite), cipherSuite)
	return s
}
func NewProtectedCryptoState(conn *Connection) *CryptoState {
	s := new(CryptoState)
	readSecret, err := conn.tls.ComputeExporter(serverPpSecret0Label, []byte{}, conn.cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}
	s.Read = newProtectedAead(readSecret, conn.cipherSuite)
	writeSecret, err := conn.tls.ComputeExporter(serverPpSecret0Label, []byte{}, conn.cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}
	s.Write = newProtectedAead(writeSecret, conn.cipherSuite)
	return s
}

func newProtectedAead(secret []byte, cipherSuite *mint.CipherSuiteParams) cipher.AEAD {
	k := mint.HkdfExpandLabel(cipherSuite.Hash, secret, "key", []byte{}, cipherSuite.KeyLen)
	iv := mint.HkdfExpandLabel(cipherSuite.Hash, secret, "iv", []byte{}, cipherSuite.IvLen)

	aead, err := newWrappedAESGCM(k, iv)
	if err != nil {
		panic(err)
	}
	return aead
}
func saltSecret(secret []byte, label string, cipherSuite *mint.CipherSuiteParams) []byte {
	salt, err := hex.DecodeString(quicVersionSalt)
	if err != nil {
		panic(err)
	}
	extracted := mint.HkdfExtract(cipherSuite.Hash, salt, secret)
	return mint.HkdfExpandLabel(cipherSuite.Hash, extracted, label, []byte{}, cipherSuite.Hash.Size())
}