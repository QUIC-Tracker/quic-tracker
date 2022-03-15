package quictracker

import "github.com/dustin/go-broadcast"

type Broadcaster struct {
	broadcast.Broadcaster
	channels []chan interface{}
	isClosed bool
}

func NewBroadcaster(buflen int) Broadcaster {
	return Broadcaster{Broadcaster: broadcast.NewBroadcaster(buflen)}
}

func (b *Broadcaster) RegisterNewChan(size int) chan interface{} {
	c := make(chan interface{}, size)
	b.channels = append(b.channels, c)
	b.Register(c)
	return c
}

func (b *Broadcaster) Close() error {
	if b.isClosed {
		return nil
	}
	b.isClosed = true
	for _, c := range b.channels {
		close(c)
	}
	return b.Broadcaster.Close()
}
func (b *Broadcaster) IsClosed() bool {
	return b.isClosed
}