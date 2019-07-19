package qlog

type PacketHeader struct {
	PacketNumber  uint64 `json:"packet_number,string"`
	PacketSize    int    `json:"packet_size"`
	PayloadLength int    `json:"payload_length,omitempty"`

	Version string          `json:"version,omitempty"`
	SCIL    string          `json:"scil,omitempty"`
	DCIL    string          `json:"dcil,omitempty"`
	SCID    string			`json:"scid,omitempty"`
	DCID    string			`json:"dcid,omitempty"`
}

type Packet struct {
	PacketType string        `json:"packet_type"`
	Header     PacketHeader  `json:"header"`
	Frames     []interface{} `json:"frames"`
}

