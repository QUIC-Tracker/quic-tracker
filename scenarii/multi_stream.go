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
	"fmt"
	_ "github.com/davecgh/go-spew/spew"
)

const (
	MS_TLSHandshakeFailed      = 1
	MS_NoTPReceived		       = 2
	MS_NotAllStreamsWereClosed = 3


)

type MultiStreamScenario struct {
	AbstractScenario
}

func NewMultiStreamScenario() *MultiStreamScenario {
	return &MultiStreamScenario{AbstractScenario{"multi_stream", 1, false}}
}
func (s *MultiStreamScenario) Run(conn *m.Connection, trace *m.Trace, debug bool) {
	conn.TLSTPHandler.MaxData = 1024 * 1024
	conn.TLSTPHandler.MaxStreamData = 1024 * 1024 / 10

	allClosed := true
	if err := CompleteHandshake(conn); err != nil {
		trace.MarkError(MS_TLSHandshakeFailed, err.Error())
		return
	}

	if conn.TLSTPHandler.EncryptedExtensionsTransportParameters == nil {
		trace.MarkError(MS_NoTPReceived, "")
		return
	}

	sendGet(conn, 4, "/index.html")

	protectedPacket := m.NewProtectedPacket(conn)
	for i := uint64(8); i <= uint64(conn.TLSTPHandler.ReceivedParameters.MaxStreamIdBidi - 4) && len(protectedPacket.Frames) < 4; i += 4 {
		if _, ok := conn.Streams[i]; !ok {
			conn.Streams[i] = new(m.Stream)
		}
		streamFrame := m.NewStreamFrame(i, conn.Streams[i], []byte("GET /index.html\r\n"), true)
		protectedPacket.Frames = append(protectedPacket.Frames, streamFrame)
	}

	conn.SendProtectedPacket(protectedPacket)

	for {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			trace.Results["error"] = err.Error()
			return
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		for streamId, stream := range conn.Streams {
			if streamId != 0 && !stream.ReadClosed {
				allClosed = false
				break
			}
		}

		if allClosed {
			conn.CloseConnection(false, 0, "")
		}
	}


	if !allClosed {
		trace.ErrorCode = MS_NotAllStreamsWereClosed
		for streamId, stream := range conn.Streams {
			trace.Results[fmt.Sprintf("stream_%d_rec_offset", streamId)] = stream.ReadOffset
			trace.Results[fmt.Sprintf("stream_%d_snd_offset", streamId)] = stream.WriteOffset
			trace.Results[fmt.Sprintf("stream_%d_snd_closed", streamId)] = stream.WriteClosed
			trace.Results[fmt.Sprintf("stream_%d_rec_closed", streamId)] = stream.ReadClosed
		}
	}
}

func sendGet(conn *m.Connection, streamId uint64, url string) {
	if _, ok := conn.Streams[streamId]; !ok {
		conn.Streams[streamId] = new(m.Stream)
	}
	streamFrame := m.NewStreamFrame(streamId, conn.Streams[streamId], []byte(fmt.Sprintf("GET %s\r\n",  url)), true)

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.Frames = append(protectedPacket.Frames, streamFrame)
	conn.SendProtectedPacket(protectedPacket)
}
