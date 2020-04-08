package agents

import (
	"errors"
	. "github.com/QUIC-Tracker/quic-tracker"
)

type StreamAgent struct {
	FrameProducingAgent
	conn             *Connection
	FlowControlAgent *FlowControlAgent
	input            chan interface{}
	streamBuffers    map[uint64][]byte
	streamClosing    map[uint64]bool
}

func (a *StreamAgent) Run(conn *Connection) {
	a.BaseAgent.Init("StreamAgent", conn.OriginalDestinationCID)
	a.FrameProducingAgent.InitFPA(conn)
	a.input = conn.StreamInput.RegisterNewChan(1000)
	a.conn = conn
	a.streamBuffers = make(map[uint64][]byte)
	a.streamClosing = make(map[uint64]bool)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-a.input:
				si := i.(StreamInput)
				if si.Reset {
					a.reset(si.StreamId, si.AppErrorCode)
				}
				if si.StopSending {
					a.stopSending(si.StreamId, si.AppErrorCode)
				}
				if len(si.Data) > 0 {
					a.send(si.StreamId, si.Data, si.Close)
				} else if si.Close {
					a.close(si.StreamId)
				}
			case args := <-a.requestFrame:
				if args.level != EncryptionLevel0RTT && args.level != EncryptionLevel1RTT && args.level != EncryptionLevelBestAppData {
					a.frames <- nil
					break
				}
				var frames []Frame
				for streamId, buf := range a.streamBuffers {
					stream := conn.Streams.Get(streamId)
					f := NewStreamFrame(streamId, stream.WriteOffset - uint64(len(buf)), nil, false)
					length := Min(len(buf) + int(f.FrameLength()), args.availableSpace)
					if length > int(f.FrameLength()) {
						f.StreamData = buf[:length-int(f.FrameLength())]
						f.LenBit = true
						f.Length = uint64(len(f.StreamData))
						if len(buf) > length {
							a.streamBuffers[streamId] = buf[length:]
						} else {
							delete(a.streamBuffers, streamId)
							if a.streamClosing[streamId] {
								delete(a.streamClosing, streamId)
								f.FinBit = true
							}
						}
						args.availableSpace -= length
						frames = append(frames, f)
					}
				}
				a.frames <- frames
			case <-a.BaseAgent.close:
				return
			}
		}
	}()
}

func (a *StreamAgent) close(streamId uint64) error {
	s := a.conn.Streams.Get(streamId)
	if IsClient(streamId) || IsBidi(streamId) {
		if s.WriteClosed {
			return errors.New("cannot close already closed stream")
		}
		s.WriteCloseOffset = s.WriteOffset
		a.conn.FrameQueue.Submit(QueuedFrame{NewStreamFrame(streamId, s.WriteOffset, nil, true), EncryptionLevelBestAppData})
		return nil
	}
	return errors.New("cannot close server uni stream")
}

func (a *StreamAgent) reset(streamId uint64, appErrorCode uint64) error {
	s := a.conn.Streams.Get(streamId)
	if IsClient(streamId) || IsBidi(streamId) {
		if s.WriteClosed {
			return errors.New("cannot reset already closed stream")
		}
		s.WriteCloseOffset = s.WriteOffset
		s.WriteClosed = true
		a.conn.FrameQueue.Submit(QueuedFrame{&ResetStream{streamId, appErrorCode, s.WriteOffset}, EncryptionLevelBestAppData})
		return nil
	}
	return errors.New("cannot reset server uni stream")
}

func (a *StreamAgent) stopSending(streamId uint64, appErrorCode uint64) error {
	if IsServer(streamId) || IsBidi(streamId) {
		if _, present := a.conn.Streams.Has(streamId); !present && IsServer(streamId) {
			return errors.New("cannot ask to stop sending on non-ready server stream")
		}
		a.conn.FrameQueue.Submit(QueuedFrame{&StopSendingFrame{streamId, appErrorCode}, EncryptionLevelBestAppData})
		return nil
	}
	return errors.New("cannot ask to stop sending on a client uni stream")
}

func (a *StreamAgent) send(streamId uint64, data []byte, close bool) error {
	s := a.conn.Streams.Get(streamId)

	if s.WriteClosed {
		return errors.New("cannot write on closed stream")
	}
	s.WriteOffset += uint64(len(data))
	s.WriteClosed = close
	if s.WriteClosed {
		s.WriteCloseOffset = s.WriteOffset
	}
	a.streamBuffers[streamId] = append(a.streamBuffers[streamId], data...)
	if close {
		a.streamClosing[streamId] = true
	}
	a.conn.PreparePacket.Submit(EncryptionLevelBestAppData)
	return nil
}
