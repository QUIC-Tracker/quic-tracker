package masterthesis

type Trace struct {
	Commit          string `json:"commit"`
	Scenario        string `json:"scenario"`
	ScenarioVersion int `json:"scenario_version"`
	Host            string `json:"host"`
	Ip              string `json:"ip"`
	Results         map[string]interface{} `json:"results"`
	StartedAt       int64 `json:"started_at"`
	Duration        uint64 `json:"duration"`
	ErrorCode       uint8 `json:"error_code"`
}
