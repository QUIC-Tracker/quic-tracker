package main

import (
	"crypto/cipher"
	"github.com/bifurcation/mint"
)

const (  // See https://tools.ietf.org/html/draft-ietf-quic-tls-05#section-5.2.2
	clientPpSecret0Label = "EXPORTER-QUIC client 1-RTT Secret"
	serverPpSecret0Label = "EXPORTER-QUIC server 1-RTT Secret"
)

type CryptoState struct {
	read  cipher.AEAD
	write cipher.AEAD
}
func NewCleartextCryptoState() *CryptoState {
	s := new(CryptoState)
	s.read = &aeadFNV{}
	s.write = &aeadFNV{}
	return s
}
func NewProtectedCryptoState(conn *Connection) *CryptoState {
	s := new(CryptoState)
	s.read = newProtectedAead(serverPpSecret0Label, conn.tls, conn.cipherSuite)
	s.write = newProtectedAead(clientPpSecret0Label, conn.tls, conn.cipherSuite)
	return s
}

func newProtectedAead(label string, tls *mint.Conn, cipherSuite *mint.CipherSuiteParams) cipher.AEAD {
	secret , err := tls.ComputeExporter(label, []byte{}, cipherSuite.Hash.Size())
	if err != nil {
		panic(err)
	}
	k := mint.HkdfExpandLabel(cipherSuite.Hash, secret, "key", []byte{}, cipherSuite.KeyLen)
	iv := mint.HkdfExpandLabel(cipherSuite.Hash, secret, "iv", []byte{}, cipherSuite.IvLen)

	aead, err := newWrappedAESGCM(k, iv)
	if err != nil {
		panic(err)
	}
	return aead
}