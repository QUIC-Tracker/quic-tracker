package scenarii

import (
	qt "github.com/QUIC-Tracker/quic-tracker"
	"bytes"
	"fmt"

	"time"
	"encoding/hex"
	"crypto/rand"
)

const (
	NCI_TLSHandshakeFailed       = 1
	NCI_HostDidNotProvideCID     = 2
	NCI_HostDidNotAnswerToNewCID = 3
	NCI_HostDidNotAdaptCID       = 4
	NCI_HostSentInvalidCIDLength = 5
)

type NewConnectionIDScenario struct {
	AbstractScenario
}

func NewNewConnectionIDScenario() *NewConnectionIDScenario {
	return &NewConnectionIDScenario{AbstractScenario{"new_connection_id", 1, false, nil}}
}
func (s *NewConnectionIDScenario) Run(conn *qt.Connection, trace *qt.Trace, preferredUrl string, debug bool) {
	// TODO: Flag NEW_CONNECTION_ID frames sent before TLS Handshake complete
	s.timeout = time.NewTimer(10 * time.Second)

	connAgents := s.CompleteHandshake(conn, trace, NCI_TLSHandshakeFailed)
	if connAgents == nil {
		return
	}
	defer connAgents.CloseConnection(false, 0, "")

	incPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incPackets)

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
				} else {
					trace.ErrorCode = 0
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

					if !expectingResponse { // TODO: Maybe we should provide CIDs in advance, see https://tools.ietf.org/rfcdiff?url2=draft-ietf-quic-transport-15.txt#part-34
						trace.ErrorCode = NCI_HostDidNotAnswerToNewCID // Assume it did not answer until proven otherwise
						conn.DestinationCID = nci.ConnectionId
						conn.SourceCID = scid
						conn.FrameQueue.Submit(qt.QueuedFrame{&qt.NewConnectionIdFrame{uint8(len(scid)), 0, scid, resetToken}, qt.EncryptionLevelBest})
						conn.SendHTTPGETRequest(preferredUrl, 0)
						expectingResponse = true
					}
				}
			}
		case <-s.Timeout().C:
			return
		}
	}
}
