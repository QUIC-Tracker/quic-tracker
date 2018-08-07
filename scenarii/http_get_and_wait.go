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
	SGW_AnsweredOnUnannouncedStream     = 10
)

type SimpleGetAndWaitScenario struct {
	AbstractScenario
}

func NewSimpleGetAndWaitScenario() *SimpleGetAndWaitScenario {
	return &SimpleGetAndWaitScenario{AbstractScenario{"http_get_and_wait", 1, false}}
}

func (s *SimpleGetAndWaitScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {

	/*errors := make(map[uint]bool)
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
		if receivedRequestedData && conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams < 1 {
			errors[SGW_AnsweredOnUnannouncedStream] = true
			message := fmt.Sprintf("the host sent data on stream 4 despite setting initial_max_stream_bidi to %d", conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams)
			errorMessages = append(errorMessages, message)
		}
		// end of the test, the connection has well been closed
		if len(errors) > 1 {
			trace.ErrorCode = SGW_MultipleErrors
			trace.Results["error"] = errorMessages
		} else if len(errors) == 0 {
			trace.ErrorCode = 0
		}
	}()

	conn.TLSTPHandler.MaxBidiStreams = 0
	conn.TLSTPHandler.MaxUniStreams = 0
	var p m.Packet; var err error
	if p, err = CompleteHandshake(conn); err != nil {
		errors[SGW_TLSHandshakeFailed] = true
		trace.MarkError(SGW_TLSHandshakeFailed, err.Error(), p)
		return
	}

	if conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams < 1 {
		trace.MarkError(SGW_TooLowStreamIdBidiToSendRequest, fmt.Sprintf("the remote initial_max_stream_id_bidi is %d", conn.TLSTPHandler.ReceivedParameters.MaxBidiStreams), p)
	}

	requestPacketNumber := conn.PacketNumber[m.PNSpaceAppData] + 1
	conn.SendHTTPGETRequest(preferredUrl, 4)

	receivedStreamOffsets := map[uint64]map[uint64]bool{
		0: make(map[uint64]bool),
		4: make(map[uint64]bool),
	}

	receivedAckBlocks := make(map[m.PNSpace][][]m.AckBlock)

	for p := range conn.IncomingPackets {
		switch p := p.(type) {
		case *m.ProtectedPacket:
			for _, f := range p.Frames {
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
							trace.MarkError(SGW_WrongStreamIDReceived, "", p)
						}
					} else if _, ok := receivedStreamOffsets[f2.StreamId][f2.Offset]; !ok {
						receivedStreamOffsets[f2.StreamId][f2.Offset] = true
					}
					if f2.FrameLength == 0 && !f2.FinBit {
						if _, ok := errors[SGW_EmptyStreamFrameNoFinBit]; !ok {
							errors[SGW_EmptyStreamFrameNoFinBit] = true
							message := fmt.Sprintf("received an empty Stream Frame with no Fin bit set for stream %d", f2.StreamId)
							errorMessages = append(errorMessages, message)
							trace.MarkError(SGW_EmptyStreamFrameNoFinBit, message, p)
						}
					}
				case *m.AckFrame:
					if f2.LargestAcknowledged == (conn.ExpectedPacketNumber[p.PNSpace()] & 0xffffffff00000000) | uint64(requestPacketNumber) {
						duplicated := false // the frame is a duplicate if we already received this largest acknowledged without any ack block

						// check if we already receive these ack blocks
						for _, blocks := range receivedAckBlocks[p.PNSpace()] {
							if reflect.DeepEqual(blocks, f2.AckBlocks) {
								// in this case, the ack blocks are the same and the largest acknowledged is the same
								duplicated = true
								break
							}
						}

						if duplicated {
							if _, ok := errors[SGW_RetransmittedAck]; !ok {
								errors[SGW_RetransmittedAck] = true
								message := fmt.Sprintf("received retransmitted ack for packet %d with the same ack blocks", requestPacketNumber)
								errorMessages = append(errorMessages, message)
								trace.MarkError(SGW_RetransmittedAck, message, p)
							}
						} else {
							// record the received ack blocks
							receivedAckBlocks[p.PNSpace()] = append(receivedAckBlocks[p.PNSpace()], f2.AckBlocks)
						}
					}
				case *m.ConnectionCloseFrame:
					return
				}

			}
		default:
		}
	}*/
}
