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
	"bytes"
	"fmt"
)

const (
	NCI_TLSHandshakeFailed		  = 1
	NCI_HostDidNotProvideCID      = 2
	NCI_HostDidNotAnswerToNewCID  = 3
	NCI_HostDidNotAdaptCID		  = 4
	NCI_HostSentInvalidCIDLength  = 5
)

type NewConnectionIDScenario struct {
	AbstractScenario
}

func NewNewConnectionIDScenario() *NewConnectionIDScenario {
	return &NewConnectionIDScenario{AbstractScenario{"new_connection_id", 1, false}}
}
func (s *NewConnectionIDScenario) Run(conn *m.Connection, trace *m.Trace, preferredUrl string, debug bool) {
	// TODO: Flag NEW_CONNECTION_ID frames sent before TLS Handshake complete

	if p, err := CompleteHandshake(conn); err != nil {
		trace.MarkError(NCI_TLSHandshakeFailed, err.Error(), p)
		return
	}

	trace.ErrorCode = NCI_HostDidNotProvideCID

	var expectingResponse bool
	var alternativeConnectionIDs [][]byte

	for p := range conn.IncomingPackets {
		if expectingResponse {
			if bytes.Equal(p.Header().DestinationConnectionID(), conn.SourceCID) {
				trace.MarkError(NCI_HostDidNotAdaptCID, "", p)
			} else {
				trace.ErrorCode = 0
			}
			return
		}

		if p.ShouldBeAcknowledged() {
			protectedPacket := m.NewProtectedPacket(conn)
			protectedPacket.Frames = append(protectedPacket.Frames, conn.GetAckFrame(p.PNSpace()))
			conn.SendProtectedPacket(protectedPacket)
		}

		if pp, ok := p.(*m.ProtectedPacket); ok {
			for _, frame := range pp.Frames {
				if nci, ok := frame.(*m.NewConnectionIdFrame); ok {
					if nci.Length < 4 || nci.Length > 18 {
						err := fmt.Sprintf("Connection ID length must be comprised between 4 and 18, it was %d", nci.Length)
						trace.MarkError(NCI_HostSentInvalidCIDLength, err, pp)
						conn.CloseConnection(true, m.ERR_PROTOCOL_VIOLATION, err)
					}

					alternativeConnectionIDs = append(alternativeConnectionIDs, nci.ConnectionId)

					if !expectingResponse {
						trace.ErrorCode = NCI_HostDidNotAnswerToNewCID // Assume it did not answer until proven otherwise
						conn.SourceCID = nci.ConnectionId
						conn.SendHTTPGETRequest(preferredUrl, 4)
						expectingResponse = true
					}
				}
			}
		}
	}

	trace.Results["new_connection_ids"] = alternativeConnectionIDs
}
