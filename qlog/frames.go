package qlog

type AckFrame struct {
	FrameType   string     `json:"frame_type"`
	ACKDelay    uint64     `json:"ack_delay"`
	ACKedRanges [][]uint64 `json:"acked_ranges"`

	ECT1 uint64 `json:"ect1,omitempty"`
	ECT0 uint64 `json:"ect0,omitempty"`
	CE   uint64 `json:"ce,omitempty"`
}

type StreamFrame struct {
	FrameType string `json:"frame_type"`
	ID        uint64 `json:"id"`
	Offset    uint64 `json:"offset"`
	Length    uint64 `json:"length"`
	Fin       bool   `json:"fin,omitempty"`
}

type ResetStreamFrame struct {
	FrameType   string `json:"frame_type"`
	ID          uint64 `json:"id"`
	ErrorCode   uint64 `json:"error_code"`
	FinalOffset uint64 `json:"final_offset"`
}

type ConnectionCloseFrame struct {
	FrameType  string `json:"frame_type"`
	ErrorSpace string `json:"error_space"`
	ErrorCode  uint64 `json:"error_code"`
	Reason     string `json:"reason"`
}

type MaxDataFrame struct {
	FrameType string `json:"frame_type"`
	Maximum   uint64 `json:"maximum"`
}

type MaxStreamDataFrame struct {
	FrameType string `json:"frame_type"`
	ID        uint64 `json:"id"`
	Maximum   uint64 `json:"maximum"`
}

type UnknownFrame struct {
	FrameType string `json:"frame_type"`

	TypeValue uint64 `json:"type_value"`
	Length    uint16 `json:"length"`
}
