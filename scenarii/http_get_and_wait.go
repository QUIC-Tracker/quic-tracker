/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package scenarii

import (
	m "github.com/mpiraux/master-thesis"
	"net"
	"fmt"
	"reflect"
)

const (
	SGW_TLSHandshakeFailed              = 1
	SGW_EmptyStreamFrameNoFinBit        = 2
	SGW_RetransmittedAck                = 3
	SGW_WrongStreamIDReceived           = 4
	SGW_UnknownError                    = 5
	SGW_DidNotCloseTheConnection        = 6
	SGW_MultipleErrors                  = 7
	SGW_TooLowStreamIdBidiToSendRequest = 8
	SGW_DidntReceiveTheRequestedData    = 9
)

type SimpleGetAndWaitScenario struct {
	AbstractScenario
}

func NewSimpleGetAndWaitScenario() *SimpleGetAndWaitScenario {
	return &SimpleGetAndWaitScenario{AbstractScenario{"http_get_and_wait", 1, false}}
}

func (s *SimpleGetAndWaitScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {

	errors := make(map[uint]bool)
	var errorMessages []string
	receivedRequestedData := false

	defer func() {
		if trace.ErrorCode != SGW_TLSHandshakeFailed && !receivedRequestedData {
			// the peer did not close the connection
			errors[SGW_DidntReceiveTheRequestedData] = true
			message := "nothing has been received on Stream 4"
			errorMessages = append(errorMessages, message)
			trace.ErrorCode = SGW_DidntReceiveTheRequestedData
			trace.Results["error"] = message
		}
		// end of the test, the connection has well been closed
		if len(errors) > 1 {
			trace.ErrorCode = SGW_MultipleErrors
			trace.Results["error"] = errorMessages
		} else if len(errors) == 0 {
			trace.ErrorCode = 0
		}
	}()
	conn.TLSTPHandler.MaxStreamIdBidi = 0
	conn.TLSTPHandler.MaxStreamIdUni = 0
	if err := CompleteHandshake(conn); err != nil {
		errors[SGW_TLSHandshakeFailed] = true
		trace.ErrorCode = SGW_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	if conn.TLSTPHandler.ReceivedParameters.MaxStreamIdBidi < 4 {
		trace.ErrorCode = SGW_TooLowStreamIdBidiToSendRequest
		trace.Results["error"] = fmt.Sprintf("the remote initial_max_stream_id_bidi is %d", conn.TLSTPHandler.ReceivedParameters.MaxStreamIdBidi)
	}

	pp := conn.SendHTTPGETRequest("/index.html", 4)
	requestPacketNumber := pp.Header().PacketNumber()
	conn.SendProtectedPacket(pp)

	receivedStreamOffsets := map[uint64]map[uint64]bool{
		0: make(map[uint64]bool),
		4: make(map[uint64]bool),
	}

	var receivedAckBlocks [][]m.AckBlock

	for i := 0; i < 50; i++ {
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
					if f2.StreamId == 4 {
						receivedRequestedData = true
					}
					if _, ok := receivedStreamOffsets[f2.StreamId]; !ok {
						// We received a frame on a forbidden stream
						if _, ok := errors[SGW_WrongStreamIDReceived]; !ok {
							errors[SGW_WrongStreamIDReceived] = true
							message := fmt.Sprintf("received StreamID %d", f2.StreamId)
							errorMessages = append(errorMessages, message)
							trace.ErrorCode = SGW_WrongStreamIDReceived
							trace.Results["error"] = message
						}
					} else if _, ok := receivedStreamOffsets[f2.StreamId][f2.Offset]; !ok {
						shouldBeAcked = true
						receivedStreamOffsets[f2.StreamId][f2.Offset] = true
					}
					if f2.Length == 0 && !f2.FinBit {
						if _, ok := errors[SGW_EmptyStreamFrameNoFinBit]; !ok {
							errors[SGW_EmptyStreamFrameNoFinBit] = true
							message := fmt.Sprintf("received an empty Stream Frame with no Fin bit set for stream %d", f2.StreamId)
							errorMessages = append(errorMessages, message)
							trace.ErrorCode = SGW_EmptyStreamFrameNoFinBit
							trace.Results["error"] = message
						}
					}
				case *m.AckFrame:
					if f2.LargestAcknowledged == (conn.ExpectedPacketNumber & 0xffffffff00000000) | uint64(requestPacketNumber) {
						duplicated := false // the frame is a duplicate if we already received this largest acknowledged without any ack block

						// check if we already receive these ack blocks
						for _, blocks := range receivedAckBlocks {
							if reflect.DeepEqual(blocks, f2.AckBlocks) {
								// in this case, the ack blocks are the same and the largest acknowledged is the same
								duplicated = true
								break
							}
						}

						if duplicated {
							if _, ok := errors[SGW_RetransmittedAck]; !ok {
								errors[SGW_RetransmittedAck] = true
								message := append(errorMessages, fmt.Sprintf("received retransmitted ack for packet %d with the same ack blocks", requestPacketNumber))
								errorMessages = message
								trace.ErrorCode = SGW_RetransmittedAck
								trace.Results["error"] = message
							}
						} else {
							// record the received ack blocks
							receivedAckBlocks = append(receivedAckBlocks, f2.AckBlocks)
						}
					}
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
	if conn.TLSTPHandler.ReceivedParameters.IdleTimeout <= 10 {
		// FIXME: accurate timeout measurement
		// the peer did not close the connection
		if false {
			errors[SGW_DidNotCloseTheConnection] = true
			message := fmt.Sprintf("the peer did not close the connection after waiting %d seconds", conn.TLSTPHandler.ReceivedParameters.IdleTimeout)
			errorMessages = append(errorMessages, message)
			trace.ErrorCode = SGW_DidNotCloseTheConnection
			trace.Results["error"] = message
		} else {
			trace.ErrorCode = 0
		}
	}
}
