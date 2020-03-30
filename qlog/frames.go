package qlog

type PingFrame struct {
	FrameType string `json:"frame_type"`
}

type AckFrame struct {
	FrameType   string     `json:"frame_type"`
	ACKDelay    uint64     `json:"ack_delay,string"`
	ACKedRanges [][]uint64 `json:"acked_ranges"`

	ECT1 uint64 `json:"ect1,omitempty"`
	ECT0 uint64 `json:"ect0,omitempty"`
	CE   uint64 `json:"ce,omitempty"`
}

type StreamFrame struct {
	FrameType string `json:"frame_type"`
	StreamID  uint64 `json:"stream_id,string"`
	Offset    uint64 `json:"offset,string"`
	Length    uint64 `json:"length,string"`
	Fin       bool   `json:"fin,omitempty"`
}

type ResetStreamFrame struct {
	FrameType   string `json:"frame_type"`
	StreamID    uint64 `json:"stream_id,string"`
	ErrorCode   uint64 `json:"error_code,string"`
	FinalOffset uint64 `json:"final_offset,string"`
}

type StopSendingFrame struct {
	FrameType string `json:"frame_type"`
	StreamID  uint64 `json:"stream_id,string"`
	ErrorCode uint64 `json:"error_code,string"`
}

type CryptoFrame struct {
	FrameType string `json:"frame_type"`
	Offset    uint64 `json:"offset,string"`
	Length    uint64 `json:"length,string"`
}

type NewTokenFrame struct {
	FrameType string `json:"frame_type"`
	Length    uint64 `json:"length,string"`
	Token     string `json:"token"`
}

type ConnectionCloseFrame struct {
	FrameType  string `json:"frame_type"`
	ErrorSpace string `json:"error_space"`
	ErrorCode  uint64 `json:"error_code,string"`
	Reason     string `json:"reason"`
}

type MaxDataFrame struct {
	FrameType string `json:"frame_type"`
	Maximum   uint64 `json:"maximum,string"`
}

type MaxStreamDataFrame struct {
	FrameType string `json:"frame_type"`
	StreamID  uint64 `json:"stream_id,string"`
	Maximum   uint64 `json:"maximum,string"`
}

type MaxStreamsFrame struct {
	FrameType  string `json:"frame_type"`
	StreamType `json:"stream_type"`
	Maximum    uint64 `json:"maximum,string"`
}

type DataBlockedFrame struct {
	FrameType string `json:"frame_type"`
	Limit     uint64 `json:"limit,string"`
}

type StreamDataBlockedFrame struct {
	FrameType string `json:"frame_type"`
	StreamID  uint64 `json:"stream_id,string"`
	Limit     uint64 `json:"limit,string"`
}

type StreamsBlockedFrame struct {
	FrameType  string `json:"frame_type"`
	StreamType `json:"stream_type"`
	Limit      uint64 `json:"limit,string"`
}

type NewConnectionIDFrame struct {
	FrameType      string `json:"frame_type"`
	SequenceNumber uint64 `json:"sequence_number,string"`
	RetirePriorTo  uint64 `json:"retire_prior_to,string"`
	Length         uint8  `json:"length"`
	ConnectionID   string `json:"connection_id"`
	ResetToken     string `json:"reset_token"`
}

type RetireConnectionIDFrame struct {
	FrameType      string `json:"frame_type"`
	SequenceNumber uint64 `json:"sequence_number,string"`
}

type PathChallengeFrame struct {
	FrameType string `json:"frame_type"`
	Data      string `json:"data"`
}

type PathResponseFrame struct {
	FrameType string `json:"frame_type"`
	Data      string `json:"data"`
}

type HandshakeDoneFrame struct {
	FrameType string `json:"frame_type"`
}

type UnknownFrame struct {
	FrameType    string `json:"frame_type"`
	RawFrameType uint64 `json:"raw_frame_type,string"`
}
