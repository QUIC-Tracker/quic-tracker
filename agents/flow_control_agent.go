package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"math"
)

func min(a, b uint64) uint64 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}

type reserveCreditArgs struct {
	StreamId uint64
	Credit   uint64
	Partial  bool
}

type FlowControlLimits struct {
	StreamsBidi             uint64
	StreamsUni              uint64
	MaxData                 uint64
	MaxStreamDataBidiLocal  uint64
	MaxStreamDataBidiRemote uint64
	MaxStreamDataUni        uint64
}

func (f *FlowControlLimits) Copy(tp *QuicTransportParameters) {
	f.StreamsBidi = tp.MaxBidiStreams
	f.StreamsUni = tp.MaxUniStreams
	f.MaxData = tp.MaxData
	f.MaxStreamDataBidiLocal = tp.MaxStreamDataBidiLocal
	f.MaxStreamDataBidiRemote = tp.MaxStreamDataBidiRemote
	f.MaxStreamDataUni = tp.MaxStreamDataUni
}

type FlowControlAgent struct {
	FrameProducingAgent
	LocalFC               FlowControlLimits
	RemoteFC              FlowControlLimits
	DontSlideCreditWindow bool
	reserveCredit         chan reserveCreditArgs
	creditsReserved       chan uint64
}

func (a *FlowControlAgent) InitStreamLimits(stream *Stream, streamId uint64) {
	if stream.WriteLimit == math.MaxUint64 && !IsUniServer(streamId) {
		if IsUni(streamId) {
			stream.WriteLimit = a.RemoteFC.MaxStreamDataUni
		} else if IsBidiClient(streamId) {
			stream.WriteLimit = a.RemoteFC.MaxStreamDataBidiRemote
		} else if IsBidiServer(streamId) {
			stream.WriteLimit = a.RemoteFC.MaxStreamDataBidiLocal
		}
		a.Logger.Printf("Initialised stream %d write limit to %d bytes\n", streamId, stream.WriteLimit)
	}
	if stream.ReadLimit == math.MaxUint64 && !IsUniClient(streamId) {
		if IsUni(streamId) {
			stream.ReadLimit = a.LocalFC.MaxStreamDataUni
		} else if IsBidiClient(streamId) {
			stream.ReadLimit = a.LocalFC.MaxStreamDataBidiLocal
		} else if IsBidiServer(streamId) {
			stream.ReadLimit = a.LocalFC.MaxStreamDataBidiRemote
		}
		a.Logger.Printf("Initialised stream %d read limit to %d bytes\n", streamId, stream.ReadLimit)
	}
}

func (a *FlowControlAgent) Run(conn *Connection) { // TODO: Report violation of our limits by the other peer
	a.Init("FlowControlAgent", conn.OriginalDestinationCID)
	a.FrameProducingAgent.InitFPA(conn)
	a.reserveCredit = make(chan reserveCreditArgs)
	a.creditsReserved = make(chan uint64)

	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)
	tpReceived := conn.TransportParameters.RegisterNewChan(1)

	blockedStreams := make(map[uint64]bool)
	streamsDataLimits := make(map[uint64]uint64)

	var dataReserved uint64
	var dataRead uint64
	var dataBlocked bool
	var dataLimitsChanged bool
	var uniStreamsBlocked bool
	var bidiStreamsBlocked bool
	var ready bool

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-tpReceived:
				tpLocal := conn.TLSTPHandler.QuicTransportParameters
				tpRemote := i.(QuicTransportParameters)
				a.LocalFC.Copy(&tpLocal)
				a.RemoteFC.Copy(&tpRemote)
				ready = true
			case i := <-incomingPackets:
				switch p := i.(type) {
				case *ProtectedPacket:
					for _, f := range p.GetFrames() {
						switch ft := f.(type) {
						case *MaxDataFrame:
							if a.RemoteFC.MaxData > ft.MaximumData {
								a.Logger.Printf("Ignoring non-increasing MAX_DATA\n")
								break
							}
							if ft.MaximumData > a.RemoteFC.MaxData {
								dataBlocked = false
							}
							a.RemoteFC.MaxData = ft.MaximumData
							a.Logger.Printf("Maximum Data is now %d bytes\n", a.RemoteFC.MaxData)
						case *MaxStreamsFrame:
							dest := &a.RemoteFC.StreamsBidi
							blocked := &bidiStreamsBlocked
							if ft.StreamsType == UniStreams {
								dest = &a.RemoteFC.StreamsUni
								blocked = &uniStreamsBlocked
							}
							if *dest > ft.MaximumStreams {
								a.Logger.Printf("Ignoring non-increasing MAX_STREAMS")
								break
							}
							if ft.MaximumStreams > *dest {
								*blocked = false
							}
							*dest = ft.MaximumStreams
							a.Logger.Printf("Number of %s is now %d\n", ft.StreamsType.String(), ft.MaximumStreams)
						case *MaxStreamDataFrame:
							stream := conn.Streams.Get(ft.StreamId)
							if IsUniServer(ft.StreamId) {
								// TODO: Report flow control error
								break
							}
							if stream.WriteLimit > ft.MaximumStreamData {
								a.Logger.Printf("Ignoring non-increasing MAX_STREAM_DATA")
								break
							}
							if ft.MaximumStreamData > stream.WriteLimit {
								delete(blockedStreams, ft.StreamId)
							}
							stream.WriteLimit = ft.MaximumStreamData
							a.Logger.Printf("Stream %d write limit is now %d bytes\n", stream.WriteLimit)
						case *StreamFrame:
							stream := conn.Streams.Get(ft.StreamId)

							if IsBidiServer(ft.StreamId) && (a.LocalFC.StreamsBidi == 0 || GetMaxBidiServer(a.LocalFC.StreamsBidi) < ft.StreamId) {
								// TODO: Report flow control violation
								break
							} else if IsUniServer(ft.StreamId) && (a.LocalFC.StreamsUni == 0 || GetMaxUniServer(a.LocalFC.StreamsUni) < ft.StreamId) {
								// TODO: Report flow control violation
								break
							}

							a.InitStreamLimits(stream, ft.StreamId)
							if ft.Offset+ft.Length > stream.ReadLimit {
								// TODO: Report flow control violation
								break
							}
							bufSpaceRequired := (ft.Offset + ft.Length) - stream.ReadBufferOffset
							if int64(bufSpaceRequired) <= 0 {
								break // This is a retransmit
							}
							if dataRead+bufSpaceRequired > a.LocalFC.MaxData {
								// TODO: Report flow control violation
								break
							}
							dataRead += bufSpaceRequired
							if !a.DontSlideCreditWindow {
								a.LocalFC.MaxData += bufSpaceRequired
								dataLimitsChanged = true

								stream.ReadLimit += bufSpaceRequired
								streamsDataLimits[ft.StreamId] = stream.ReadLimit
							}
						}
					}
				}
			case args := <-a.reserveCredit:
				if !ready {
					a.creditsReserved <- 0
					break
				}

				// First check that the stream can be opened
				if IsBidiClient(args.StreamId) && !bidiStreamsBlocked && (a.RemoteFC.StreamsBidi == 0 || GetMaxBidiClient(a.RemoteFC.StreamsBidi) < args.StreamId) {
					bidiStreamsBlocked = true
					conn.FrameQueue.Submit(QueuedFrame{&StreamsBlockedFrame{BidiStreams, a.RemoteFC.StreamsBidi}, EncryptionLevelBestAppData})
					a.creditsReserved <- 0
					break
				} else if IsUniClient(args.StreamId) && !uniStreamsBlocked && (a.RemoteFC.StreamsUni == 0 || GetMaxUniClient(a.RemoteFC.StreamsUni) < args.StreamId) {
					uniStreamsBlocked = false
					conn.FrameQueue.Submit(QueuedFrame{&StreamsBlockedFrame{UniStreams, a.RemoteFC.StreamsUni}, EncryptionLevelBestAppData})
					a.creditsReserved <- 0
					break
				}

				var creditReserved uint64
				stream := conn.Streams.Get(args.StreamId)
				a.InitStreamLimits(stream, args.StreamId)

				if args.Partial {
					args.Credit = min(min(args.Credit, stream.WriteLimit-stream.WriteReserved), min(args.Credit, a.RemoteFC.MaxData-dataReserved))
				}

				// Second, check that enough credits can be reserved
				if stream.WriteReserved+args.Credit <= stream.WriteLimit {
					if dataReserved+args.Credit <= a.RemoteFC.MaxData {
						stream.WriteReserved += args.Credit
						dataReserved += args.Credit
						creditReserved = args.Credit
						a.Logger.Printf("Reserved %d bytes for stream %d\n", args.Credit, args.StreamId)
					}
				}

				if !blockedStreams[args.StreamId] && (stream.WriteReserved >= stream.WriteLimit || (creditReserved < args.Credit)) {
					blockedStreams[args.StreamId] = true
					conn.FrameQueue.Submit(QueuedFrame{&StreamDataBlockedFrame{args.StreamId, stream.WriteLimit}, EncryptionLevelBestAppData})
				}

				if !dataBlocked && dataReserved >= a.LocalFC.MaxData {
					dataBlocked = true
					conn.FrameQueue.Submit(QueuedFrame{&DataBlockedFrame{stream.WriteLimit}, EncryptionLevelBestAppData})
				}

				a.creditsReserved <- creditReserved
			case args := <-a.requestFrame:
				if args.level != EncryptionLevel0RTT && args.level != EncryptionLevel1RTT {
					a.frames <- nil
					break
				}
				var allFrames []Frame
				if dataLimitsChanged {
					allFrames = append(allFrames, &MaxDataFrame{a.LocalFC.MaxData})
					dataLimitsChanged = false
				}
				for streamId, limit := range streamsDataLimits {
					allFrames = append(allFrames, &MaxStreamDataFrame{streamId, limit})
					delete(streamsDataLimits, streamId)
				}
				if dataBlocked {
					allFrames = append(allFrames, &DataBlockedFrame{a.RemoteFC.MaxData})
				}
				if bidiStreamsBlocked {
					allFrames = append(allFrames, &StreamsBlockedFrame{BidiStreams, a.RemoteFC.StreamsBidi})
				}
				if uniStreamsBlocked {
					allFrames = append(allFrames, &StreamsBlockedFrame{UniStreams, a.RemoteFC.StreamsUni})
				}
				for streamId, _ := range blockedStreams {
					allFrames = append(allFrames, &StreamDataBlockedFrame{streamId, conn.Streams.Get(streamId).WriteLimit})
				}

				var frames []Frame
				totalSize := 0
				for _, f := range allFrames {
					fLen := int(f.FrameLength())
					if totalSize+fLen < args.availableSpace {
						frames = append(frames, f)
						totalSize += fLen
					}
				}
				a.frames <- frames
			case <-a.close:
				return
			}
		}
	}()
}

func (a *FlowControlAgent) ReserveCredit(streamId uint64, amount uint64) uint64 {
	select {
	case a.reserveCredit <- reserveCreditArgs{streamId, amount, false}:
		return <-a.creditsReserved
	case <-a.close:
		return 0
	}
}

func (a *FlowControlAgent) ReserveAtMost(streamId uint64, amount uint64) uint64 {
	select {
	case a.reserveCredit <- reserveCreditArgs{streamId, amount, true}:
		return <-a.creditsReserved
	case <-a.close:
		return 0
	}
}
