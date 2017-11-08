package masterthesis

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
	"io"
	"net"
	"time"
)

type connBuffer struct {
	r *bytes.Buffer
	w *bytes.Buffer
}

func (p *connBuffer) Read(data []byte) (n int, err error) {
	n, err = p.r.Read(data)

	// Suppress bytes.Buffer's EOF on an empty buffer
	if err == io.EOF {
		err = nil
	}
	return
}

func (p *connBuffer) Write(data []byte) (n int, err error) {
	return p.w.Write(data)
}

func (p *connBuffer) Close() error {
	return nil
}

func (p *connBuffer) LocalAddr() net.Addr                { return nil }
func (p *connBuffer) RemoteAddr() net.Addr               { return nil }
func (p *connBuffer) SetDeadline(t time.Time) error      { return nil }
func (p *connBuffer) SetReadDeadline(t time.Time) error  { return nil }
func (p *connBuffer) SetWriteDeadline(t time.Time) error { return nil }

func newConnBuffer() *connBuffer {
	return &connBuffer{
		bytes.NewBuffer(nil),
		bytes.NewBuffer(nil),
	}
}

func (p *connBuffer) input(data []byte) error {
	_, err := p.r.Write(data)
	return err
}

func (p *connBuffer) getOutput() []byte {
	b := p.w.Bytes()
	p.w.Reset()
	return b
}

func (p *connBuffer) OutputLen() int {
	return p.w.Len()
}
