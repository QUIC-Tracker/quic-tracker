package agents

import . "github.com/QUIC-Tracker/quic-tracker"

type HTTPAgent interface {
	SendRequest(path, method, authority string, headers map[string]string)
	HTTPResponseReceived() Broadcaster
}

type HTTPResponse interface {
	StreamID() uint64
	Headers() []HTTPHeader
	Body() []byte
}

type HTTP09Response struct {
	streamID uint64
	body     []byte
}

func (r *HTTP09Response) StreamID() uint64      { return r.streamID }
func (r *HTTP09Response) Headers() []HTTPHeader { return nil }
func (r *HTTP09Response) Body() []byte          { return r.body }

type HTTP09Agent struct {
	BaseAgent
	conn                 *Connection
	nextRequestStream    uint64
	httpResponseReceived Broadcaster
}

func (a *HTTP09Agent) Run(conn *Connection) {
	a.Init("HTTP09Agent", conn.OriginalDestinationCID)
	a.httpResponseReceived = NewBroadcaster(1000)
	a.conn = conn
}

func (a *HTTP09Agent) SendRequest(path, method, authority string, headers map[string]string) {
	streamID := a.nextRequestStream
	a.conn.SendHTTP09GETRequest(path, streamID)
	responseChan := a.conn.Streams.Get(a.nextRequestStream).ReadChan.RegisterNewChan(1000)

	go func() {
		response := HTTP09Response{streamID: streamID}
		for i := range responseChan {
			data := i.([]byte)
			response.body = append(response.body, data...)
		}
		a.httpResponseReceived.Submit(response)
	}()

	a.nextRequestStream += 4
}

func (a *HTTP09Agent) HTTPResponseReceived() Broadcaster { return a.httpResponseReceived }
