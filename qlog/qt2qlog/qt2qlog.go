package qt2qlog

import (
	"encoding/hex"
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"strconv"
)

var qlogPacketType = map[PacketType]string{
	Initial:           "initial",
	Handshake:         "handshake",
	ZeroRTTProtected:  "0RTT",
	ShortHeaderPacket: "1RTT",
	Retry:             "retry",
	VersionNegotiation: "version_negotiation",
}

func ConvertPacket(p Packet) *qlog.Packet {
	j := &qlog.Packet{}
	switch p.(type) {
	case *InitialPacket, *HandshakePacket, *ZeroRTTProtectedPacket, *ProtectedPacket:
		j.PacketType = qlogPacketType[p.Header().PacketType()]
	case *RetryPacket:
		j.PacketType = qlogPacketType[Retry]
	case *VersionNegotiationPacket:
		j.PacketType = qlogPacketType[VersionNegotiation]
	default:
		j.PacketType = "unknown"
	}
	// TODO handle PacketSize computation here
	switch p.(type) {
	case *VersionNegotiationPacket, *RetryPacket, *StatelessResetPacket:
	default:
		j.Header.PacketNumber = uint64(p.Header().PacketNumber())
	}

	switch h := p.Header().(type) {
		case *ShortHeader:
			j.Header.DCIL = strconv.Itoa(int(h.DestinationCID.CIDL()))
			j.Header.DCID = h.DestinationCID.String()
		case *LongHeader:
			j.Header.PayloadLength = int(h.Length.Value)
			j.Header.SCIL = strconv.Itoa(int(h.SourceCID.CIDL()))
			j.Header.SCID = h.SourceCID.String()
			j.Header.DCIL = strconv.Itoa(int(h.DestinationCID.CIDL()))
			j.Header.DCID = h.DestinationCID.String()
	}

	switch fr := p.(type) {
	case Framer:
		j.Frames = convertFrames(fr.GetFrames())
	}
	if p.ReceiveContext().WasBuffered {
		j.Trigger = "keys_unavailable"
	}
	return j
}

func convertFrames(frames []Frame) []interface{} {
	var ret []interface{}
	for _, f := range frames {
		var qf interface{}
		switch ft := f.(type) {
		case *PingFrame:
			qf = &qlog.PingFrame{"ping"}
		case *AckFrame:
			qf = ackFrameToQLog(ft)
		case *AckECNFrame:
			qf = ackECNFrameToQLog(ft)
		case *StreamFrame:
			qf = &qlog.StreamFrame{
				FrameType: "stream",
				StreamID: ft.StreamId,
				Offset: ft.Offset,
				Length: ft.Length,
				Fin: ft.FinBit,
			}
		case *ResetStream:
			qf = &qlog.ResetStreamFrame{
				FrameType: "reset_stream",
				StreamID: ft.StreamId,
				ErrorCode: ft.ApplicationErrorCode,
				FinalOffset: ft.FinalSize,
			}
		case *StopSendingFrame:
			qf = &qlog.StopSendingFrame{
				FrameType: "stop_sending",
				StreamID: ft.StreamId,
				ErrorCode: ft.ApplicationErrorCode,
			}
		case *CryptoFrame:
			qf = &qlog.CryptoFrame{
				FrameType: "crypto",
				Offset: ft.Offset,
				Length: ft.Length,
			}
		case *NewTokenFrame:
			qf = &qlog.NewTokenFrame{
				FrameType: "new_token",
				Length: uint64(len(ft.Token)),
				Token: hex.EncodeToString(ft.Token),
			}
		case *ConnectionCloseFrame:
			qf = &qlog.ConnectionCloseFrame{FrameType: "connection_close",
				ErrorSpace: "transport",
				ErrorCode: ft.ErrorCode,
				Reason: ft.ReasonPhrase,
			}
		case *ApplicationCloseFrame:
			qf = &qlog.ConnectionCloseFrame{
				FrameType: "connection_close",
				ErrorSpace: "application",
				ErrorCode: ft.ErrorCode,
				Reason: ft.ReasonPhrase,
			}
		case *MaxDataFrame:
			qf = &qlog.MaxDataFrame{
				FrameType: "max_data",
				Maximum: ft.MaximumData,
			}
		case *MaxStreamDataFrame:
			qf = &qlog.MaxStreamDataFrame{
				FrameType: "max_stream_data",
				StreamID: ft.StreamId,
				Maximum: ft.MaximumStreamData,
			}
		case *MaxStreamsFrame:
			qf = maxStreamsToQLog(ft)
		case *NewConnectionIdFrame:
			qf = &qlog.NewConnectionIDFrame{
				FrameType:      "new_connection_id",
				SequenceNumber: ft.Sequence,
				RetirePriorTo:  ft.RetirePriorTo,
				Length:         uint8(len(ft.ConnectionId)),
				ConnectionID:   hex.EncodeToString(ft.ConnectionId),
				ResetToken:     hex.EncodeToString(ft.StatelessResetToken[:]),
			}
		case *RetireConnectionId:
			qf = &qlog.RetireConnectionIDFrame{
				FrameType: "retire_connection_id",
				SequenceNumber: ft.SequenceNumber,
			}
		case *PathChallenge:
			qf = &qlog.PathChallengeFrame{
				FrameType: "path_challenge",
				Data: hex.EncodeToString(ft.Data[:]),
			}
		case *PathResponse:
			qf = &qlog.PathResponseFrame{
				FrameType: "path_response",
				Data: hex.EncodeToString(ft.Data[:]),
			}
		case *HandshakeDoneFrame:
			qf = &qlog.HandshakeDoneFrame{
				FrameType: "handshake_done",
			}
		case *PaddingFrame:
			continue
		default:
			qf = unknownFrameToQLog(ft)
		}
		ret = append(ret, qf)
	}
	return ret
}

func ackFrameToQLog(a *AckFrame) *qlog.AckFrame {
	q := qlog.AckFrame{FrameType: "ack", ACKDelay: a.AckDelay}

	largest := uint64(a.LargestAcknowledged)
	rang := a.AckRanges[0].AckRange

	q.ACKedRanges = append(q.ACKedRanges, []uint64{largest - rang, largest})
	largest -= rang

	for _, ar := range a.AckRanges[1:] {
		q.ACKedRanges = append(q.ACKedRanges, []uint64{largest - ar.Gap - 1 - ar.AckRange, largest - ar.Gap - 1})
		largest -= ar.Gap + 1 + ar.AckRange
	}
	return &q
}

func ackECNFrameToQLog(a *AckECNFrame) *qlog.AckFrame {
	q := ackFrameToQLog(&a.AckFrame)
	q.ECT0 = a.ECT0Count
	q.ECT1 = a.ECT1Count
	q.CE = a.ECTCECount
	return q
}

func maxStreamsToQLog(m *MaxStreamsFrame) *qlog.MaxStreamsFrame {
	sType := qlog.StreamTypeBidi
	if m.StreamsType == UniStreams {
		sType = qlog.StreamTypeUni
	}
	return &qlog.MaxStreamsFrame{FrameType: "max_streams", StreamType: sType, Maximum: m.MaximumStreams}
}

func unknownFrameToQLog(u Frame) *qlog.UnknownFrame {
	return &qlog.UnknownFrame{FrameType: "unknown", RawFrameType: uint64(u.FrameType())}
}

func ConvertPacketLost(packetType PacketType, number PacketNumber, frames []Frame, trigger string) *qlog.PacketLost {
	j := &qlog.PacketLost{Frames: convertFrames(frames), Trigger: trigger}
	if pType, ok := qlogPacketType[packetType]; ok {
		j.PacketType = pType
	} else {
		j.PacketType = "unknown"
	}
	j.PacketNumber = uint64(number)
	return j
}

func ConvertPacketBuffered(packetType PacketType, trigger string) *qlog.PacketBuffered {
	var typeStr string
	if pType, ok := qlogPacketType[packetType]; ok {
		typeStr = pType
	} else {
		typeStr = "unknown"
	}
	return &qlog.PacketBuffered{PacketType: typeStr, Trigger: trigger}
}