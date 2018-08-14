package lib

/*This file originates from https://github.com/ekr/minq and is subject to the
following license and copyright

-------------------------------------------------------------------------------

The MIT License (MIT)

Copyright (c) 2016 Eric Rescorla

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

*/

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"hash/fnv"
)

// Definition for AEAD using 64-bit FNV-1a
type aeadFNV struct {
}

func (a *aeadFNV) NonceSize() int {
	return 12
}
func (a *aeadFNV) Overhead() int {
	return 8
}

func (a *aeadFNV) Seal(dst []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	h := fnv.New64a()
	h.Write(aad)
	h.Write(plaintext)
	res := EncodeArgs(plaintext, h.Sum64())
	dst = append(dst, res...)
	return dst
}

func (a *aeadFNV) Open(dst []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	if len(ciphertext) < 8 {
		return nil, fmt.Errorf("Data too short to contain authentication tag")
	}
	pt := ciphertext[:len(ciphertext)-8]
	at := ciphertext[len(ciphertext)-8:]
	h := fnv.New64a()
	h.Write(aad)
	h.Write(pt)

	at2 := EncodeArgs(h.Sum64())

	if !bytes.Equal(at, at2) {
		return nil, fmt.Errorf("Invalid authentication tag")
	}

	dst = append(dst, pt...)
	return pt, nil
}

// aeadWrapper contains an existing AEAD object and does the
// QUIC nonce masking.
type aeadWrapper struct {
	iv     []byte
	cipher cipher.AEAD
}

func (a *aeadWrapper) NonceSize() int {
	return a.cipher.NonceSize()
}
func (a *aeadWrapper) Overhead() int {
	return a.cipher.Overhead()
}

func (a *aeadWrapper) fmtNonce(in []byte) []byte {
	// The input nonce is actually a packet number.

	nonce := make([]byte, a.NonceSize())
	copy(nonce[len(nonce)-len(in):], in)
	for i, b := range a.iv {
		nonce[i] ^= b
	}

	return nonce
}

func (a *aeadWrapper) Seal(dst []byte, nonce []byte, plaintext []byte, aad []byte) []byte {
	ret := a.cipher.Seal(dst, a.fmtNonce(nonce), plaintext, aad)

	return ret
}

func (a *aeadWrapper) Open(dst []byte, nonce []byte, ciphertext []byte, aad []byte) ([]byte, error) {
	ret, err := a.cipher.Open(dst, a.fmtNonce(nonce), ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return ret, err
}

func NewWrappedAESGCM(key []byte, iv []byte) (cipher.AEAD, error) {
	a, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(a)
	if err != nil {
		return nil, err
	}

	return &aeadWrapper{iv, aead}, nil
}
