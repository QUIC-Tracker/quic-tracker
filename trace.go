package masterthesis

type Trace struct {
	Commit          string                 `json:"commit"`
	Scenario        string                 `json:"scenario"`
	ScenarioVersion int                    `json:"scenario_version"`
	Host            string                 `json:"host"`
	Ip              string                 `json:"ip"`
	Results         map[string]interface{} `json:"results"`
	StartedAt       int64                  `json:"started_at"`
	Duration        uint64                 `json:"duration"`
	ErrorCode       uint8                  `json:"error_code"`
	Stream          []TracePacket          `json:"stream"`
}

type Direction string

const ToServer Direction = "to_server"
const ToClient Direction = "to_client"

type TracePacket struct {
	Direction Direction `json:"direction"`
	Timestamp int64     `json:"timestamp"`
	Data      []byte    `json:"data"`
}
