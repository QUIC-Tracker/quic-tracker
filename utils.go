package quictracker

import "github.com/dustin/go-broadcast"

type Broadcaster struct {
	broadcast.Broadcaster
}

func NewBroadcaster(buflen int) Broadcaster {
	return Broadcaster{broadcast.NewBroadcaster(buflen)}
}

func (b *Broadcaster) RegisterNewChan(size int) chan interface{} {
	c := make(chan interface{}, size)
	b.Register(c)
	return c
}