package agents

import (
	"container/heap"
	. "github.com/QUIC-Tracker/quic-tracker"
)

var FramePriority = map[FrameType]int{
	ConnectionCloseType:    1,
	ApplicationCloseType:   2,
	PathResponseType:       3,
	AckType:                4,
	AckECNType:             5,
	CryptoType:             6,
	PingType:               7,
	NewConnectionIdType:    8,
	RetireConnectionIdType: 9,
	PathChallengeType:      10,
	ResetStreamType:        11,
	StopSendingType:        12,
	MaxDataType:            13,
	MaxStreamDataType:      14,
	MaxStreamsType:         15,
	MaxStreamsType + 1:     16,
	DataBlockedType:        17,
	StreamDataBlockedType:  18,
	StreamsBlockedType:     19,
	StreamsBlockedType + 1: 20,
	NewTokenType:           21,
	StreamType:             22,
	PaddingFrameType:       23,
}

type item struct {
	value    Frame
	priority int
	index    int
}

type FramePriorityQueue []*item

func NewFramePriorityQueue() *FramePriorityQueue {
	pq := make(FramePriorityQueue, 0)
	heap.Init(&pq)
	return &pq
}

func (pq FramePriorityQueue) Len() int { return len(pq) }

func (pq FramePriorityQueue) Less(i, j int) bool {
	return pq[i].priority < pq[j].priority
}

func (pq FramePriorityQueue) Swap(i, j int) {
	if pq.Len() < 2 {
		return
	}
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *FramePriorityQueue) Push(x interface{}) {
	n := len(*pq)
	item := new(item)
	f := x.(Frame)
	item.value = f
	item.priority = FramePriority[f.FrameType()]
	item.index = n
	*pq = append(*pq, item)
}

func (pq *FramePriorityQueue) Pop() interface{} {
	if pq.Len() < 1 {
		return nil
	}
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1
	*pq = old[0 : n-1]
	return item.value
}

func (pq *FramePriorityQueue) Peek() Frame {
	if pq.Len() < 1 {
		return nil
	}
	items := *pq
	return items[len(items)-1].value
}

type FrameQueueAgent struct {
	FrameProducingAgent
}

// The FrameQueueAgent collects all the frames that should be packed into packets and order them by frame type priority.
// Each type of frame is given a level of priority as expressed in FramePriority.
func (a *FrameQueueAgent) Run(conn *Connection) {
	a.BaseAgent.Init("FrameQueueAgent", conn.OriginalDestinationCID)
	a.FrameProducingAgent.InitFPA(conn)

	frameBuffer := map[EncryptionLevel]*FramePriorityQueue{
		EncryptionLevelInitial:     NewFramePriorityQueue(),
		EncryptionLevel0RTT:        NewFramePriorityQueue(),
		EncryptionLevelHandshake:   NewFramePriorityQueue(),
		EncryptionLevel1RTT:        NewFramePriorityQueue(),
		EncryptionLevelBest:        NewFramePriorityQueue(),
		EncryptionLevelBestAppData: NewFramePriorityQueue(),
	}

	incFrames := conn.FrameQueue.RegisterNewChan(1000)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-incFrames:
				qf := i.(QueuedFrame)
				heap.Push(frameBuffer[qf.EncryptionLevel], qf.Frame)
				a.Logger.Printf("Received a 0x%02x frame for encryption level %s\n", qf.FrameType(), qf.EncryptionLevel)
				conn.PreparePacket.Submit(qf.EncryptionLevel)
			case args := <-a.requestFrame:
				var frames []Frame
				buffer := frameBuffer[args.level]
				var i interface{}
				for i = heap.Pop(buffer); i != nil && args.availableSpace >= int(i.(Frame).FrameLength()); i = heap.Pop(buffer) {
					frames = append(frames, i.(Frame))
					args.availableSpace -= int(i.(Frame).FrameLength())
				}
				if i != nil {
					heap.Push(buffer, i)
				}

				if i != nil && args.availableSpace < int(i.(Frame).FrameLength()) {
					a.Logger.Printf("Unable to put %d-byte frame into %d-byte buffer\n", i.(Frame).FrameLength(), args.availableSpace)
					a.conn.PreparePacket.Submit(args.level)
				}
				a.frames <- frames
			case <-a.close:
				return
			}
		}
	}()
}
