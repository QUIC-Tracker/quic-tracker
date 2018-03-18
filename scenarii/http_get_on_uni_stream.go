package scenarii

import (
	m "github.com/mpiraux/master-thesis"
	"net"
	"fmt"
)

const (
	GS2_TLSHandshakeFailed               = 1
	GS2_TooLowStreamIdUniToSendRequest   = 2
	GS2_ReceivedDataOnStream2            = 3
	GS2_ReceivedDataOnUnauthorizedStream = 4
	GS2_AnswersToARequestOnAForbiddenStreamID = 5
)

type GetOnStream2Scenario struct {
	AbstractScenario
}

func NewGetOnStream2Scenario() *GetOnStream2Scenario {
	return &GetOnStream2Scenario{AbstractScenario{"http_get_on_uni_stream", 1, false}}
}

func (s *GetOnStream2Scenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {

	errors := make(map[uint]bool)
	var errorMessages []string

	conn.Streams[3] = new(m.Stream)

	conn.TLSTPHandler.MaxStreamIdBidi = 1
	conn.TLSTPHandler.MaxStreamIdUni = 3
	if err := CompleteHandshake(conn); err != nil {
		errors[GS2_TLSHandshakeFailed] = true
		trace.ErrorCode = GS2_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	if conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni < 2 {
		trace.ErrorCode = GS2_TooLowStreamIdUniToSendRequest
		trace.Results["error"] = fmt.Sprintf("the remote initial_max_stream_id_uni is %d", conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni)
	}


	pp := conn.SendHTTPGETRequest("/index.html", 2)
	conn.SendProtectedPacket(pp)



	for i := 0 ; i < 50 ; i++ {
		readPacket, err, _ := conn.ReadNextPacket()
		if err != nil {
			switch e := err.(type) {
			case *net.OpError:
				// the peer timed out without closing the connection
				if e.Timeout() {
					if false {
						// FIXME: accurate timeout computation
						trace.ErrorCode = SGW_DidNotCloseTheConnection
						errors[SGW_DidNotCloseTheConnection] = true
						message := fmt.Sprintf("the peer did not close the connection after waiting %d seconds", conn.TLSTPHandler.ReceivedParameters.IdleTimeout)
						errorMessages = append(errorMessages, message)
						trace.Results["error"] = message
						errorMessages = append(errorMessages, message)
					} else {
					 	trace.ErrorCode = 0
					}
				} else {
					trace.ErrorCode = SGW_UnknownError
					errors[SGW_UnknownError] = true
					trace.Results["error"] = e.Error()
					errorMessages = append(errorMessages, e.Error())
				}
			}
			return
		}

		switch pp := readPacket.(type) {
		case *m.ProtectedPacket:
			shouldBeAcked := false
			for _, f := range pp.Frames {
				switch f2 := f.(type) {
				case *m.StreamFrame:
					if f2.StreamId == 2 {
						trace.ErrorCode = GS2_ReceivedDataOnStream2
						return
					} else if f2.StreamId > 3 {
						trace.ErrorCode = GS2_ReceivedDataOnUnauthorizedStream
					} else if f2.StreamId == 3 && conn.TLSTPHandler.ReceivedParameters.MaxStreamIdUni < 2 {
						// they answered us even if we sent a get request on a Stream ID above their initial_max_stream_id_uni
						trace.ErrorCode = GS2_AnswersToARequestOnAForbiddenStreamID
						return
					}
					shouldBeAcked = true
				case *m.ConnectionCloseFrame:
					return
				}
			}
			if shouldBeAcked {
				toSend := m.NewProtectedPacket(conn)
				toSend.Frames = append(toSend.Frames, conn.GetAckFrame())
				conn.SendProtectedPacket(toSend)
			}

		default:
			toSend := m.NewHandshakePacket(nil, []m.AckFrame{*conn.GetAckFrame()}, nil, conn)
			conn.SendHandshakeProtectedPacket(toSend)
		}

	}
}
