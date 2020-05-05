package scenarii

import (
	"bytes"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"

	"crypto/rand"
	"encoding/hex"
)

const (
	NCI_TLSHandshakeFailed       = 1
	NCI_HostDidNotProvideCID     = 2
	NCI_HostDidNotAnswerToNewCID = 3
	NCI_HostDidNotAdaptCID       = 4
	NCI_HostSentInvalidCIDLength = 5
	NCI_NoCIDAllowed			 = 6
)

type NewConnectionIDScenario struct {
	AbstractScenario
}

func NewNewConnectionIDScenario() *NewConnectionIDScenario {
	return &NewConnectionIDScenario{AbstractScenario{name: "new_connection_id", version: 2}}
}
func (s *NewConnectionIDScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredPath string, debug bool) {
	incPackets := conn.IncomingPackets.RegisterNewChan(1000)

	connAgents := s.CompleteHandshake(conn, trace, NCI_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	if conn.TLSTPHandler.ReceivedParameters.ActiveConnectionIdLimit < 2 {
		trace.ErrorCode = NCI_NoCIDAllowed
		return
	}

	trace.ErrorCode = NCI_HostDidNotProvideCID

	var expectingResponse bool
	var alternativeConnectionIDs []string
	defer func() { trace.Results["new_connection_ids"] = alternativeConnectionIDs }()

	scid := make([]byte, 8)
	var resetToken [16]byte
	rand.Read(scid)
	rand.Read(resetToken[:])

	for {
		select {
		case i := <-incPackets:
			p := i.(qt.Packet)
			if expectingResponse {
				if !bytes.Equal(p.Header().DestinationConnectionID(), conn.SourceCID) {
					trace.MarkError(NCI_HostDidNotAdaptCID, "", p)
				} else if conn.Streams.Get(0).ReadClosed {
					trace.ErrorCode = 0
					s.Finished()
				}
				break
			}

			if pp, ok := p.(*qt.ProtectedPacket); ok {
				for _, frame := range pp.GetAll(qt.NewConnectionIdType) {
					nci := frame.(*qt.NewConnectionIdFrame)

					if nci.Length < 4 || nci.Length > 18 {
						err := fmt.Sprintf("Connection ID length must be comprised between 4 and 18, it was %d", nci.Length)
						trace.MarkError(NCI_HostSentInvalidCIDLength, err, pp)
					}

					alternativeConnectionIDs = append(alternativeConnectionIDs, hex.EncodeToString(nci.ConnectionId))

					if !expectingResponse {
						trace.ErrorCode = NCI_HostDidNotAnswerToNewCID // Assume it did not answer until proven otherwise
						conn.DestinationCID = nci.ConnectionId
						conn.SourceCID = scid
						conn.FrameQueue.Submit(qt.QueuedFrame{&qt.NewConnectionIdFrame{1, 0, uint8(len(scid)), scid, resetToken}, qt.EncryptionLevelBest})
						conn.SendHTTP09GETRequest(preferredPath, 0)
						expectingResponse = true
					}
				}
			}
		case <-conn.ConnectionClosed:
			return
		case <-s.Timeout():
			return
		}
	}
}
