package quictracker

import (
	"testing"
	"bytes"
	"github.com/davecgh/go-spew/spew"
)

func TestByteIntervalList_Add(t *testing.T) {
	l := NewbyteIntervalList()
	l.Add(byteInterval{1, 2})
	l.Add(byteInterval{4, 5})

	if ok, a, e := iterEquals(l, []byteInterval{{1, 2}, {4, 5}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l.Add(byteInterval{2, 4})

	if ok, a, e := iterEquals(l, []byteInterval{{1, 5}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l.Add(byteInterval{6, 8})
	if ok, a, e := iterEquals(l, []byteInterval{{1, 5}, {6, 8}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}
}

func TestByteIntervalList_Fill(t *testing.T) {
	l := NewbyteIntervalList()
	l.Add(byteInterval{1, 2})
	l.Add(byteInterval{4, 6})

	l.Fill(byteInterval{4,5})

	if ok, a, e := iterEquals(l, []byteInterval{{1, 2}, {5, 6}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l.Add(byteInterval{2, 5})
	if ok, a, e := iterEquals(l, []byteInterval{{1, 6}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l.Fill(byteInterval{3,4})

	if ok, a, e := iterEquals(l, []byteInterval{{1, 2}, {5, 6}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l.Fill(byteInterval{1,2})

	if ok, a, e := iterEquals(l, []byteInterval{{5, 6}}); !ok {
		l.Println()
		if a != e {
			t.Error("Expected ", e, "got ", a)
		} else {
			t.Error("Lengthes differ")
		}
	}

	l = NewbyteIntervalList()

}

func TestStreamAddToRead (t *testing.T) {
	s := NewStream()

	readChan := make(chan interface{}, 10)
	s.ReadChan.Register(readChan)
	s.addToRead(&StreamFrame{Offset: 4, Length: 4, StreamData:[]byte{4, 5, 6, 7}})

	select {
	case _ = <- readChan:
		t.Error("Should not return data")
	default:
	}

	s.addToRead(&StreamFrame{Offset: 0, Length: 4, StreamData: []byte{0, 1, 2, 3}})

	var dataRead []byte

read:
	for {
		select {
		case i := <- readChan:
			data := i.([]byte)
			dataRead = append(dataRead, data...)
		default:
			break read
		}
	}

	if !bytes.Equal(dataRead, []byte{0, 1, 2, 3, 4, 5, 6, 7}) {
		spew.Dump(dataRead)
		t.Error("Should be equal")
	}

	s.addToRead(&StreamFrame{Offset: 12, Length: 4, StreamData: []byte{4, 5, 6, 7}})
	s.addToRead(&StreamFrame{Offset: 16, Length: 4, StreamData: []byte{8, 9, 10, 11}, FinBit: true})

	if s.ReadClosed {
		t.Error("Should not be closed yet")
	}

	s.addToRead(&StreamFrame{Offset: 8, Length: 4, StreamData: []byte{0, 1, 2, 3}})

	if !s.ReadClosed {
		t.Error("Should be closed now")
	}

read2:
	for {
		select {
		case i := <- readChan:
			data := i.([]byte)
			dataRead = append(dataRead, data...)
		default:
			break read2
		}
	}

	if !bytes.Equal(dataRead, []byte{0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
		spew.Dump(dataRead)
		t.Error("Should be equal")
	}
}

func iterEquals(l *byteIntervalList, expected []byteInterval) (bool, *byteInterval, *byteInterval) {
	i := 0
	if l.Len() != len(expected) {
		return false, nil, nil
	}
	for n := l.Front(); n != nil && i < len(expected); n = n.Next() {
		if n.Value != expected[i] {
			return false, &n.Value, &expected[i]
		}
		i++
	}
	return true, nil, nil
}
