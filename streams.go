package quictracker

import (
	"fmt"
	"math"
	"sync"
)

type StreamsType bool

const (
	BidiStreams StreamsType = false
	UniStreams              = true
)

func (s StreamsType) String() string {
	if s == BidiStreams {
		return "bidirectional streams"
	}
	return "unidirectional streams"
}

func IsBidi(streamId uint64) bool   { return streamId&2 == 0 }
func IsUni(streamId uint64) bool    { return streamId&2 == 2 }
func IsClient(streamId uint64) bool { return streamId&1 == 0 }
func IsServer(streamId uint64) bool { return streamId&1 == 1 }

func IsBidiClient(streamId uint64) bool { return IsBidi(streamId) && IsClient(streamId) }
func IsBidiServer(streamId uint64) bool { return IsBidi(streamId) && IsServer(streamId) }
func IsUniClient(streamId uint64) bool  { return IsUni(streamId) && IsClient(streamId) }
func IsUniServer(streamId uint64) bool  { return IsUni(streamId) && IsServer(streamId) }

func GetMaxBidiClient(limit uint64) uint64 { return 0 + limit*4 }
func GetMaxBidiServer(limit uint64) uint64 { return 1 + limit*4 }
func GetMaxUniClient(limit uint64) uint64  { return 2 + limit*4 }
func GetMaxUniServer(limit uint64) uint64  { return 3 + limit*4 }

type StreamInput struct {
	StreamId     uint64
	Data         []byte
	Close        bool
	Reset        bool
	StopSending  bool
	AppErrorCode uint64
}

type Streams struct {
	streams map[uint64]*Stream
	lock    *sync.Mutex
	input   *Broadcaster
}

func (s Streams) Get(streamId uint64) *Stream {
	s.lock.Lock()
	if s.streams[streamId] == nil {
		s.streams[streamId] = NewStream()
	}
	s.lock.Unlock()
	return s.streams[streamId]
}

func (s Streams) GetAll() map[uint64]*Stream {
	return s.streams
}

func (s Streams) Has(streamId uint64) (*Stream, bool) {
	a, b := s.streams[streamId]
	return a, b
}

func (s Streams) NumberOfServerStreamsOpen() int {
	count := 0
	for streamID, _ := range s.streams {
		if streamID%2 == 1 {
			count++
		}
	}
	return count
}

func (s Streams) Close(streamId uint64) {
	s.input.Submit(StreamInput{StreamId: streamId, Data: nil, Close: true})
}

func (s Streams) Reset(streamId uint64, appErrorCode uint64) {
	s.input.Submit(StreamInput{StreamId: streamId, AppErrorCode: appErrorCode, Reset: true})
}

func (s Streams) StopSending(streamId uint64, appErrorCode uint64) {
	s.input.Submit(StreamInput{StreamId: streamId, AppErrorCode: appErrorCode, StopSending: true})
}

func (s Streams) Send(streamId uint64, data []byte, close bool) {
	s.input.Submit(StreamInput{StreamId: streamId, Data: data, Close: close})
}

type CryptoStreams map[PNSpace]*Stream

func (s CryptoStreams) Get(space PNSpace) *Stream {
	if s[space] == nil {
		s[space] = NewStream()
	}

	return s[space]
}

type Stream struct {
	ReadOffset  uint64
	WriteOffset uint64

	ReadLimit        uint64
	ReadBufferOffset uint64
	WriteLimit       uint64
	WriteReserved    uint64

	ReadData  []byte
	WriteData []byte

	ReadChan        Broadcaster
	maxReadReceived uint64
	gaps            *byteIntervalList

	ReadClosed       bool
	ReadCloseOffset  uint64
	WriteClosed      bool
	WriteCloseOffset uint64

	readFeedback chan interface{}
}

func NewStream() *Stream {
	s := new(Stream)
	s.ReadChan = NewBroadcaster(1024)
	s.readFeedback = make(chan interface{}, 1)
	s.ReadChan.Register(s.readFeedback)
	s.gaps = NewbyteIntervalList().Init()
	s.ReadCloseOffset = math.MaxUint64
	s.WriteCloseOffset = math.MaxUint64
	s.ReadLimit = math.MaxUint64
	s.WriteLimit = math.MaxUint64
	return s
}

func (s *Stream) addToRead(f *StreamFrame) { // TODO: Flag implementations that retransmit different data for a given offset
	if f.Offset > s.ReadCloseOffset {
		// TODO: report this: write past fin bit
	}
	if f.FinBit {
		if s.ReadCloseOffset != math.MaxUint64 && s.ReadCloseOffset != f.Offset+f.Length {
			// TODO: report this: new fin bit offset
		} else {
			s.ReadCloseOffset = f.Offset + f.Length
		}
	}

	if f.Offset == s.ReadOffset && f.Offset == s.maxReadReceived {
		s.ReadOffset += f.Length
		s.maxReadReceived = s.ReadOffset
		s.ReadData = append(s.ReadData, f.StreamData...)
		s.ReadChan.Submit(f.StreamData)
		<-s.readFeedback // Makes sure it propagates before returning
	} else if f.Offset+f.Length > s.maxReadReceived {
		if s.maxReadReceived < f.Offset {
			s.gaps.Add(byteInterval{s.maxReadReceived, f.Offset})
		}
		s.maxReadReceived = f.Offset + f.Length
		newSlice := make([]byte, int(f.Offset)+len(f.StreamData), int(f.Offset)+len(f.StreamData))
		copy(newSlice, s.ReadData)
		copy(newSlice[f.Offset:int(f.Offset)+len(f.StreamData)], f.StreamData)
		s.ReadData = newSlice
	} else {
		s.gaps.Fill(byteInterval{f.Offset, f.Offset + f.Length})
		copy(s.ReadData[f.Offset:], f.StreamData)
		var firstGap uint64
		if s.gaps.len > 0 {
			firstGap = s.gaps.Front().Value.start
		} else {
			firstGap = uint64(len(s.ReadData))
		}

		if s.ReadOffset < firstGap {
			s.ReadChan.Submit(s.ReadData[s.ReadOffset:firstGap])
			<-s.readFeedback // Makes sure it propagates before returning
			s.ReadOffset = firstGap
		}
	}

	if s.ReadOffset == s.ReadCloseOffset && !s.ReadClosed {
		s.ReadClosed = true
		s.ReadChan.Close()
	}
}

// Linked list implementation from the Go standard library.
type byteIntervalElement struct {
	// Next and previous pointers in the doubly-linked list of elements.
	// To simplify the implementation, internally a list l is implemented
	// as a ring, such that &l.root is both the next element of the last
	// list element (l.Back()) and the previous element of the first list
	// element (l.Front()).
	next, prev *byteIntervalElement

	// The list to which this element belongs.
	list *byteIntervalList

	// The value stored with this element.
	Value byteInterval
}

// Next returns the next list element or nil.
func (e *byteIntervalElement) Next() *byteIntervalElement {
	if p := e.next; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// Prev returns the previous list element or nil.
func (e *byteIntervalElement) Prev() *byteIntervalElement {
	if p := e.prev; e.list != nil && p != &e.list.root {
		return p
	}
	return nil
}

// byteIntervalList is a linked list of byteIntervals.
type byteIntervalList struct {
	root byteIntervalElement // sentinel list element, only &root, root.prev, and root.next are used
	len  int                 // current list length excluding (this) sentinel element
}

func (l *byteIntervalList) Add(b byteInterval) {
	n := l.Front()
	if n == nil {
		l.PushFront(b)
	} else {
		for n != nil {
			if b.IsBefore(n.Value) {
				l.InsertBefore(b, n)
				break
			}
			n = n.Next()
		}
		if n == nil {
			l.PushBack(b)
		}
	}
	l.ensureConsistency()
}

func (l *byteIntervalList) Fill(b byteInterval) {
	n := l.Front()
	for n != nil {
		if b.Overlap(n.Value) {
			for _, f := range n.Value.Exclude(b) {
				l.InsertBefore(f, n)
			}
			next := n.Next()
			l.Remove(n)
			n = next
		} else {
			n = n.Next()
		}
	}
	l.ensureConsistency()
}

func (l *byteIntervalList) ensureConsistency() {
	var p *byteIntervalElement = nil
	n := l.Front()

	for n != nil {
		if p != nil && p.Value.Overlap(n.Value) {
			l.Remove(p)
			p = l.InsertBefore(p.Value.Merge(n.Value), n)
			l.Remove(n)
			n = p.Next()
		} else {
			p = n
			n = n.Next()
		}
	}
}

func (l *byteIntervalList) Println() {
	fmt.Print("{")
	for n := l.Front(); n != nil; n = n.Next() {
		n.Value.Print()
	}
	fmt.Println("}")
}

// Init initializes or clears list l.
func (l *byteIntervalList) Init() *byteIntervalList {
	l.root.next = &l.root
	l.root.prev = &l.root
	l.len = 0
	return l
}

// NewbyteIntervalList returns an initialized list.
func NewbyteIntervalList() *byteIntervalList { return new(byteIntervalList).Init() }

// Len returns the number of elements of list l.
// The complexity is O(1).
func (l *byteIntervalList) Len() int { return l.len }

// Front returns the first element of list l or nil if the list is empty.
func (l *byteIntervalList) Front() *byteIntervalElement {
	if l.len == 0 {
		return nil
	}
	return l.root.next
}

// Back returns the last element of list l or nil if the list is empty.
func (l *byteIntervalList) Back() *byteIntervalElement {
	if l.len == 0 {
		return nil
	}
	return l.root.prev
}

// lazyInit lazily initializes a zero List value.
func (l *byteIntervalList) lazyInit() {
	if l.root.next == nil {
		l.Init()
	}
}

// insert inserts e after at, increments l.len, and returns e.
func (l *byteIntervalList) insert(e, at *byteIntervalElement) *byteIntervalElement {
	n := at.next
	at.next = e
	e.prev = at
	e.next = n
	n.prev = e
	e.list = l
	l.len++
	return e
}

// insertValue is a convenience wrapper for insert(&Element{Value: v}, at).
func (l *byteIntervalList) insertValue(v byteInterval, at *byteIntervalElement) *byteIntervalElement {
	return l.insert(&byteIntervalElement{Value: v}, at)
}

// remove removes e from its list, decrements l.len, and returns e.
func (l *byteIntervalList) remove(e *byteIntervalElement) *byteIntervalElement {
	e.prev.next = e.next
	e.next.prev = e.prev
	e.next = nil // avoid memory leaks
	e.prev = nil // avoid memory leaks
	e.list = nil
	l.len--
	return e
}

// Remove removes e from l if e is an element of list l.
// It returns the element value e.Value.
// The element must not be nil.
func (l *byteIntervalList) Remove(e *byteIntervalElement) byteInterval {
	if e.list == l {
		// if e.list == l, l must have been initialized when e was inserted
		// in l or l == nil (e is a zero Element) and l.remove will crash
		l.remove(e)
	}
	return e.Value
}

// PushFront inserts a new element e with value v at the front of list l and returns e.
func (l *byteIntervalList) PushFront(v byteInterval) *byteIntervalElement {
	l.lazyInit()
	return l.insertValue(v, &l.root)
}

// PushBack inserts a new element e with value v at the back of list l and returns e.
func (l *byteIntervalList) PushBack(v byteInterval) *byteIntervalElement {
	l.lazyInit()
	return l.insertValue(v, l.root.prev)
}

// InsertBefore inserts a new element e with value v immediately before mark and returns e.
// If mark is not an element of l, the list is not modified.
// The mark must not be nil.
func (l *byteIntervalList) InsertBefore(v byteInterval, mark *byteIntervalElement) *byteIntervalElement {
	if mark.list != l {
		return nil
	}
	// see comment in List.Remove about initialization of l
	return l.insertValue(v, mark.prev)
}

// InsertAfter inserts a new element e with value v immediately after mark and returns e.
// If mark is not an element of l, the list is not modified.
// The mark must not be nil.
func (l *byteIntervalList) InsertAfter(v byteInterval, mark *byteIntervalElement) *byteIntervalElement {
	if mark.list != l {
		return nil
	}
	// see comment in List.Remove about initialization of l
	return l.insertValue(v, mark)
}

// MoveToFront moves element e to the front of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *byteIntervalList) MoveToFront(e *byteIntervalElement) {
	if e.list != l || l.root.next == e {
		return
	}
	// see comment in List.Remove about initialization of l
	l.insert(l.remove(e), &l.root)
}

// MoveToBack moves element e to the back of list l.
// If e is not an element of l, the list is not modified.
// The element must not be nil.
func (l *byteIntervalList) MoveToBack(e *byteIntervalElement) {
	if e.list != l || l.root.prev == e {
		return
	}
	// see comment in List.Remove about initialization of l
	l.insert(l.remove(e), l.root.prev)
}

// MoveBefore moves element e to its new position before mark.
// If e or mark is not an element of l, or e == mark, the list is not modified.
// The element and mark must not be nil.
func (l *byteIntervalList) MoveBefore(e, mark *byteIntervalElement) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.remove(e), mark.prev)
}

// MoveAfter moves element e to its new position after mark.
// If e or mark is not an element of l, or e == mark, the list is not modified.
// The element and mark must not be nil.
func (l *byteIntervalList) MoveAfter(e, mark *byteIntervalElement) {
	if e.list != l || e == mark || mark.list != l {
		return
	}
	l.insert(l.remove(e), mark)
}

// PushBackList inserts a copy of an other list at the back of list l.
// The lists l and other may be the same. They must not be nil.
func (l *byteIntervalList) PushBackList(other *byteIntervalList) {
	l.lazyInit()
	for i, e := other.Len(), other.Front(); i > 0; i, e = i-1, e.Next() {
		l.insertValue(e.Value, l.root.prev)
	}
}

// PushFrontList inserts a copy of an other list at the front of list l.
// The lists l and other may be the same. They must not be nil.
func (l *byteIntervalList) PushFrontList(other *byteIntervalList) {
	l.lazyInit()
	for i, e := other.Len(), other.Back(); i > 0; i, e = i-1, e.Prev() {
		l.insertValue(e.Value, &l.root)
	}
}

type byteInterval struct {
	start uint64
	end   uint64
}

func (b byteInterval) In(offset uint64) bool        { return b.start <= offset && offset <= b.end }
func (b byteInterval) IsBefore(o byteInterval) bool { return b.end <= o.start }
func (b byteInterval) Overlap(o byteInterval) bool {
	return (o.start <= b.end && o.end >= b.end) ||
		(b.start <= o.end && b.end >= o.end) ||
		(b.start <= o.start && b.end >= o.end) ||
		(o.start <= b.start && o.end >= b.end)
}
func (b byteInterval) Merge(o byteInterval) byteInterval {
	return byteInterval{min(b.start, o.start), max(b.end, o.end)}
}
func (b byteInterval) Exclude(o byteInterval) []byteInterval {
	if o.start > b.start && o.end < b.end {
		return []byteInterval{{b.start, o.start - 1}, {o.end + 1, b.end}}
	} else if o.start <= b.start && o.end < b.end {
		return []byteInterval{{o.end, b.end}}
	} else if o.end > b.end {
		return []byteInterval{{b.start, o.start}}
	}
	return nil
}

func (b byteInterval) Print() {
	fmt.Printf("[%d, %d]", b.start, b.end)
}
