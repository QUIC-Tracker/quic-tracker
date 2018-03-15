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
	m "masterthesis"
)

const (
	NCI_TLSHandshakeFailed		  = 1
	NCI_HostDidNotProvideCID      = 2
	NCI_HostDidNotAnswerToNewCID  = 3
	NCI_HostDidNotAdaptCID		  = 4
)

type NewConnectionIDScenario struct {
	AbstractScenario
}

func NewNewConnectionIDScenario() *NewConnectionIDScenario {
	return &NewConnectionIDScenario{AbstractScenario{"new_connection_id", 1, false}}
}
func (s *NewConnectionIDScenario) Run(conn *m.Connection, trace *m.Trace) {
	// TODO: Flag NEW_CONNECTION_ID frames sent before TLS Handshake complete

	if err := CompleteHandshake(conn); err != nil {
		trace.ErrorCode = NCI_TLSHandshakeFailed
		trace.Results["error"] = err.Error()
		return
	}

	trace.ErrorCode = NCI_HostDidNotProvideCID

	var expectingResponse bool
	var alternativeConnectionIDs []uint64
	for {
		packet, err, _ := conn.ReadNextPacket()

		if err != nil {
			trace.Results["error"] = err.Error()
			return
		}

		if expectingResponse {
			if packet.Header().ConnectionId() != conn.ConnectionId {
				trace.ErrorCode = NCI_HostDidNotAdaptCID
			} else {
				trace.ErrorCode = 0
			}
			return
		}

		if packet.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame())
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := packet.(*m.ProtectedPacket); ok {
			for _, frame := range pp.Frames {
				if nci, ok := frame.(*m.NewConnectionIdFrame); ok {
					alternativeConnectionIDs = append(alternativeConnectionIDs, nci.ConnectionId)

					if !expectingResponse {
						trace.ErrorCode = NCI_HostDidNotAnswerToNewCID // Assume it did not answer until proven otherwise
						conn.ConnectionId = nci.ConnectionId
						conn.PacketNumber += uint64(m.GetPacketGap(conn))
						conn.SendHTTPGETRequest("/index.html")
						expectingResponse = true
					}
				}
			}
		}

	}
}
