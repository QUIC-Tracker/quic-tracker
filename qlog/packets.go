package qlog

type PacketTrigger string

const (
	PacketTriggerReordering = "retransmit_reorder"
	PacketTriggerTimeout    = "retransmit_timeout"
	PacketTriggerPTO        = "pro_probe"
	PacketTriggerCrypto     = "retransmit_crypto"
	PacketTriggerBWProbe    = "cc_bandwidth_probe"
)

type PacketHeader struct {
	PacketNumber  uint64 `json:"packet_number,string"`
	PacketSize    int    `json:"packet_size,omitempty"`
	PayloadLength int    `json:"payload_length,omitempty"`

	Version string `json:"version,omitempty"`
	SCIL    string `json:"scil,omitempty"`
	DCIL    string `json:"dcil,omitempty"`
	SCID    string `json:"scid,omitempty"`
	DCID    string `json:"dcid,omitempty"`
}

type Packet struct {
	PacketType string        `json:"packet_type"`
	Header     PacketHeader  `json:"header"`
	Frames     []interface{} `json:"frames,omitempty"`

	IsCoalesced bool   `json:"is_coalesced,omitempty"`
	Trigger     string `json:"trigger,omitempty"`
}

type PacketLost struct {
	PacketType   string        `json:"packet_type"`
	PacketNumber uint64        `json:"packet_number,string"`
	Frames       []interface{} `json:"frames"`
	Trigger      string        `json:"trigger"`
}

type PacketBuffered struct {
	PacketType string `json:"packet_type"`
	Trigger    string `json:"trigger"`
}
