package qt2qlog

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/qlog"
	"strconv"
)

var qlogPacketType = map[PacketType]string{
	Initial:           "INITIAL",
	Handshake:         "HANDSHAKE",
	ZeroRTTProtected:  "0RTT",
	ShortHeaderPacket: "1RTT",
	Retry:             "RETRY",
	// TODO: Add VN
}

func ConvertPacket(p Packet) *qlog.Packet {
	j := &qlog.Packet{}
	if _, ok := qlogPacketType[p.Header().PacketType()]; ok {
		j.PacketType = qlogPacketType[p.Header().PacketType()]
	} else {
		j.PacketType = "UNKNOWN"
	}
	j.Header.PacketNumber = uint64(p.Header().PacketNumber())
	// TODO handle PacketSize computation here
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
		for _, f := range fr.GetFrames() {
			var qf interface{}
			switch ft := f.(type) {
			case *AckFrame:
				qf = ackFrameToQLog(ft)
			case *StreamFrame:
				qf = streamFrameToQLog(ft)
			case *ResetStream:
				qf = resetStreamToQLog(ft)
			case *ConnectionCloseFrame:
				qf = connectionCloseToQLog(ft)
			case *ApplicationCloseFrame:
				qf = applicationCloseToQLog(ft)
			case *MaxDataFrame:
				qf = maxDataToQLog(ft)
			case *MaxStreamDataFrame:
				qf = maxStreamDataFrameToQLog(ft)
			case PaddingFrame, *PaddingFrame:
				continue
			default:
				qf = unknownFrameToQLog(ft)
			}
			j.Frames = append(j.Frames, qf)
		}
	}
	return j
}

func ackFrameToQLog(a *AckFrame) *qlog.AckFrame {
	q := qlog.AckFrame{}
	q.FrameType = "ACK"
	q.ACKDelay = a.AckDelay

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

func streamFrameToQLog(s *StreamFrame) *qlog.StreamFrame {
	q := qlog.StreamFrame{}
	q.FrameType = "STREAM"
	q.ID = s.StreamId
	q.Offset = s.Offset
	q.Length = s.Length
	q.Fin = s.FinBit
	return &q
}

func resetStreamToQLog(r *ResetStream) *qlog.ResetStreamFrame {
	q := qlog.ResetStreamFrame{}
	q.FrameType = "RESET_STREAM"
	q.ID = r.StreamId
	q.ErrorCode = r.ApplicationErrorCode
	q.FinalOffset = r.FinalSize
	return &q
}

func connectionCloseToQLog(c *ConnectionCloseFrame) *qlog.ConnectionCloseFrame {
	q := qlog.ConnectionCloseFrame{}
	q.FrameType = "CONNECTION_CLOSE"
	q.ErrorSpace = "TRANSPORT"
	q.ErrorCode = c.ErrorCode
	q.Reason = c.ReasonPhrase
	return &q
}

func applicationCloseToQLog(a *ApplicationCloseFrame) *qlog.ConnectionCloseFrame {
	q := qlog.ConnectionCloseFrame{}
	q.FrameType = "CONNECTION_CLOSE"
	q.ErrorSpace = "APPLICATION"
	q.ErrorCode = a.ErrorCode
	q.Reason = a.ReasonPhrase
	return &q
}

func maxDataToQLog(m *MaxDataFrame) *qlog.MaxDataFrame {
	q := qlog.MaxDataFrame{}
	q.FrameType = "MAX_DATA"
	q.Maximum = m.MaximumData
	return &q
}

func maxStreamDataFrameToQLog(m *MaxStreamDataFrame) *qlog.MaxStreamDataFrame {
	q := qlog.MaxStreamDataFrame{}
	q.FrameType = "MAX_STREAM_DATA"
	q.ID = m.StreamId
	q.Maximum = m.MaximumStreamData
	return &q
}

func unknownFrameToQLog(u Frame) *qlog.UnknownFrame {
	q := qlog.UnknownFrame{}
	q.FrameType = "UNKNOWN"
	q.TypeValue = uint64(u.FrameType())
	q.Length = u.FrameLength()
	return &q
}
