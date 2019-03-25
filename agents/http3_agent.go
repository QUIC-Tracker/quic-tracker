package agents

import (
	"bytes"
	"errors"
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/http3"
	"github.com/davecgh/go-spew/spew"
	"math"
)

type HTTP3Response struct {
	HTTP09Response
	headers  []HTTPHeader

	fin              bool
	headersRemaining int
	totalProcessed   uint64
	totalReceived    uint64
}

func (r HTTP3Response) Complete() bool {
	return r.fin && r.totalReceived > 0 && r.totalProcessed == r.totalReceived && r.headersRemaining == 0
}

func (r HTTP3Response) Headers() []HTTPHeader { return r.headers }

type HTTP3FrameReceived struct {
	StreamID uint64
	Frame    http3.HTTPFrame
}

type streamData struct {
	streamID uint64
	data     []byte
}

// The HTTP3 Agent is TODO
type HTTP3Agent struct {
	BaseAgent
	conn                 *Connection
	DisableQPACKStreams	 bool
	QPACK                QPACKAgent
	QPACKEncoderOpts     uint32
	HTTPResponseReceived Broadcaster //type: HTTP3Response
	FrameReceived        Broadcaster //type: HTTP3FrameReceived
	streamData           chan streamData
	streamDataBuffer     map[uint64]*bytes.Buffer
	responseBuffer       map[uint64]*HTTP3Response
	controlStreamID      uint64
	peerControlStreamID  uint64
	nextRequestStream    uint64
}

const (
	HTTPNoStream uint64 = math.MaxUint64
)

func (a *HTTP3Agent) Run(conn *Connection) {
	a.Init("HTTP3Agent", conn.OriginalDestinationCID)
	a.conn = conn
	a.QPACK = QPACKAgent{EncoderStreamID: 6, DecoderStreamID: 10, DisableStreams: a.DisableQPACKStreams}
	a.QPACK.Run(conn)

	a.HTTPResponseReceived = NewBroadcaster(1000)
	a.FrameReceived = NewBroadcaster(1000)

	frameReceived := a.FrameReceived.RegisterNewChan(1000)
	incomingPackets := conn.IncomingPackets.RegisterNewChan(1000)

	encodedHeaders := a.QPACK.EncodedHeaders.RegisterNewChan(1000)
	decodedHeaders := a.QPACK.DecodedHeaders.RegisterNewChan(1000)

	a.controlStreamID = uint64(2)
	a.peerControlStreamID = HTTPNoStream
	peerControlStream := make(chan interface{}, 1000)
	peerControlStreamBuffer := new(bytes.Buffer)
	a.conn.Streams.Send(a.controlStreamID, []byte{'C'}, false)
	a.sendFrameOnStream(http3.NewSETTINGS(nil), a.controlStreamID, false)

	a.streamData = make(chan streamData)
	a.streamDataBuffer = make(map[uint64]*bytes.Buffer)
	a.responseBuffer = make(map[uint64]*HTTP3Response)

	var settingsReceived bool
	settingsHeaderTableSize := uint64(4096)
	settingsQPACKBlockedStreams := uint64(100)

	go func() {
		defer a.Logger.Println("Agent terminated")
		defer close(a.closed)
		for {
			select {
			case i := <-incomingPackets:
				p := i.(Packet)
				if p.PNSpace() == PNSpaceAppData {
					for _, f := range p.(Framer).GetAll(StreamType) {
						s := f.(*StreamFrame)
						if s.Offset == 0 && s.StreamId&0x2 == 2 {
							if s.StreamData[0] == 'C' {
								if a.peerControlStreamID != HTTPNoStream {
									a.Logger.Printf("Peer attempted to open another control stream on stream %d\n", s.StreamId)
									continue
								}
								a.peerControlStreamID = s.StreamId
								conn.Streams.Get(s.StreamId).ReadChan.Register(peerControlStream)
								if s.Length > 1 {
									peerControlStream <- s.StreamData[1:] // Submits the rest as normal control stream data
								}
								a.Logger.Printf("Peer opened control stream on stream %d\n", s.StreamId)
							}
						}
					}
				}
			case i := <-peerControlStream:
				peerControlStreamBuffer.Write(i.([]byte))
				a.attemptDecoding(a.peerControlStreamID, peerControlStreamBuffer)
			case sd := <-a.streamData:
				streamBuffer := a.streamDataBuffer[sd.streamID]
				streamBuffer.Write(sd.data)
				a.attemptDecoding(sd.streamID, streamBuffer)
			case i := <-frameReceived:
				fr := i.(HTTP3FrameReceived)
				a.Logger.Printf("Received a %s frame on stream %d\n", fr.Frame.Name(), fr.StreamID)
				switch f := fr.Frame.(type) {
				case *http3.HEADERS:
					a.QPACK.DecodeHeaders <- EncodedHeaders{fr.StreamID, f.HeaderBlock}
					var response *HTTP3Response
					var ok bool
					if response, ok = a.responseBuffer[fr.StreamID]; !ok {
						a.Logger.Printf("Received encoded headers for stream %d, but no matching response found\n", fr.StreamID)
						continue
					}
					response.headersRemaining++
					response.totalProcessed += f.WireLength()
				case *http3.DATA:
					var response *HTTP3Response
					var ok bool
					if response, ok = a.responseBuffer[fr.StreamID]; !ok {
						a.Logger.Printf("%s frame for stream %d does not match any request\n", f.Name(), fr.StreamID)
						continue
					}
					response.body = append(a.responseBuffer[fr.StreamID].body, f.Payload...)
					response.totalProcessed += f.WireLength()
					a.checkResponse(response)
				case *http3.SETTINGS:
					if settingsReceived {
						a.Logger.Printf("Received a SETTINGS frame for the second time!\n")
						continue
					}
					settingsReceived = true
					for _, s := range f.Settings {
						if s.Identifier == http3.SETTINGS_HEADER_TABLE_SIZE {
							settingsHeaderTableSize = s.Value.Value
						} else if s.Identifier == http3.SETTINGS_QPACK_BLOCKED_STREAMS {
							settingsQPACKBlockedStreams = s.Value.Value
						}
					}
					dynamicTableSize := uint(1024)
					if a.DisableQPACKStreams {
						dynamicTableSize = 0
					}
					if dynamicTableSize > uint(settingsHeaderTableSize) {
						dynamicTableSize = uint(settingsHeaderTableSize)
					}
					a.QPACK.InitEncoder(uint(settingsHeaderTableSize), dynamicTableSize, uint(settingsQPACKBlockedStreams), a.QPACKEncoderOpts)
				default:
					spew.Dump(fr)
				}
			case i := <-decodedHeaders:
				dHdrs := i.(DecodedHeaders)
				var response *HTTP3Response
				var ok bool
				if response, ok = a.responseBuffer[dHdrs.StreamID]; !ok {
					a.Logger.Printf("Received decoded headers for stream %d, but no matching response found\n", dHdrs.StreamID)
					continue
				}
				response.headersRemaining--
				response.headers = append(a.responseBuffer[dHdrs.StreamID].headers, dHdrs.Headers...)
				a.checkResponse(response)
			case i := <-encodedHeaders:
				eHdrs := i.(EncodedHeaders)
				a.sendFrameOnStream(http3.NewHEADERS(eHdrs.Headers), eHdrs.StreamID, true)
				a.Logger.Printf("Sent a %d-byte long block of headers on stream %d\n", len(eHdrs.Headers), eHdrs.StreamID)
			case <-a.close:
				return
			}
		}
	}()
}
func (a *HTTP3Agent) sendFrameOnStream(frame http3.HTTPFrame, streamID uint64, fin bool) {
	buf := new(bytes.Buffer)
	frame.WriteTo(buf)
	a.conn.Streams.Send(streamID, buf.Bytes(), fin)
}
func (a *HTTP3Agent) attemptDecoding(streamID uint64, buffer *bytes.Buffer) {
	var l VarInt
	var err error
	for l, err = peekVarInt(buffer); err == nil && buffer.Len() >= l.Length+1+int(l.Value); l, err = peekVarInt(buffer) {
		reader := bytes.NewReader(buffer.Next(l.Length + 1 + int(l.Value)))
		frame := http3.ReadHTTPFrame(reader)
		a.FrameReceived.Submit(HTTP3FrameReceived{streamID, frame})
	}
	if err == nil {
		a.Logger.Printf("Unable to parse %d byte-long frame on stream %d, %d bytes missing\n", l.Value, streamID, int(l.Value)-(buffer.Len()-l.Length-1))
	}
}
func (a *HTTP3Agent) checkResponse(response *HTTP3Response) {
	if response.Complete() {
		a.HTTPResponseReceived.Submit(*response)
		a.Logger.Printf("A %d-byte long response on stream %d is complete\n", response.totalProcessed, response.streamID)
	}
}
func (a *HTTP3Agent) SendRequest(path, method, authority string, headers map[string]string) {
	if headers == nil {
		headers = make(map[string]string)
	}

	if _, ok := headers["user-agent"]; !ok {
		headers["user-agent"] = "QUIC-Tracker/" + GitCommit()
	}

	hdrs := []HTTPHeader{
		{":method", method},
		{":scheme", "https"},
		{":authority", authority},
		{":path", path},
	}
	for k, v := range headers {
		hdrs = append(hdrs, HTTPHeader{k, v})
	}

	streamID := a.nextRequestStream
	stream := a.conn.Streams.Get(streamID)
	streamChan := stream.ReadChan.RegisterNewChan(1000)
	a.streamDataBuffer[streamID] = new(bytes.Buffer)
	response := &HTTP3Response{HTTP09Response: HTTP09Response{streamID: streamID}}
	a.responseBuffer[streamID] = response

	go func() { // Pipes the data from the response stream to the agent
		for {
			select {
			case i := <-streamChan:
				if i == nil {
					return
				}
				data := i.([]byte)
				a.streamData <- streamData{streamID, i.([]byte)}
				response.totalReceived += uint64(len(data))
				if stream.ReadClosed || response.totalReceived == stream.ReadCloseOffset {
					response.fin = true
					a.checkResponse(response)
				}
			case <-a.close:
				return
			}

		}
		stream.ReadChan.Unregister(streamChan)
	}()

	a.QPACK.EncodeHeaders <- DecodedHeaders{streamID, hdrs}
	a.nextRequestStream += 4
}

func peekVarInt(buffer *bytes.Buffer) (VarInt, error) {
	if buffer.Len() == 0 {
		return VarInt{}, errors.New("no more byte to read")
	}
	return ReadVarInt(bytes.NewReader(buffer.Bytes()))
}
