package quictracker

import (
	"os/exec"
	"time"
	"strings"
	"unsafe"
	"github.com/mpiraux/pigotls"
)

// Contains the result of a test run against a given host.
type Trace struct {
	Commit              string                 `json:"commit"`     // The git commit that versions the code that produced the trace
	Scenario            string                 `json:"scenario"`   // The id of the scenario that produced the trace
	ScenarioVersion     int                    `json:"scenario_version"`
	Host                string                 `json:"host"`       // The host against which the scenario was run
	Ip                  string                 `json:"ip"`         // The IP that was resolved for the given host
	Results             map[string]interface{} `json:"results"`    // A dictionary that allows to report scenario-specific results
	StartedAt           int64                  `json:"started_at"` // The time at which the scenario started in epoch seconds
	Duration            uint64                 `json:"duration"`   // Its duration in epoch milliseconds
	ErrorCode           uint8                  `json:"error_code"` // A scenario-specific error code that reports its verdict
	Stream              []TracePacket          `json:"stream"`     // A clear-text copy of the packets that were sent and received
	Pcap                []byte                 `json:"pcap"`       // The packet capture file associated with the trace
	QLog                interface{}            `json:"qlog"`       // The QLog trace captured during the test run
	ClientRandom        []byte                 `json:"client_random"`
	Secrets				map[pigotls.Epoch]Secrets `json:"secrets"`
}

type Secrets struct {
	Epoch pigotls.Epoch `json:"epoch"`
	Read  []byte        `json:"read"`
	Write []byte        `json:"write"`
}

func NewTrace(scenarioName string, scenarioVersion int, host string) *Trace {
	trace := Trace{
		Scenario:        scenarioName,
		ScenarioVersion: scenarioVersion,
		Commit:          GitCommit(),
		Host:            host,
		StartedAt:       time.Now().Unix(),
		Results:         make(map[string]interface{}),
	}

	return &trace
}

func (t *Trace) AddPcap(conn *Connection, cmd *exec.Cmd) error {
	content, err := StopPcapCapture(conn, cmd)
	if err != nil {
		return err
	}
	t.Pcap = content
	return err
}

func (t *Trace) MarkError(error uint8, message string, packet Packet) {
	t.ErrorCode = error
	if message != "" {
		t.Results["error"] = message
	}
	if packet == nil {
		return
	}
	for _, tp := range t.Stream {
		if tp.Pointer == packet.Pointer() {
			tp.IsOfInterest = true
			return
		}
	}
}

func (t *Trace) AttachTo(conn *Connection) {
	conn.ReceivedPacketHandler = func(data []byte, origin unsafe.Pointer) {
		t.Stream = append(t.Stream, TracePacket{Direction: ToClient, Timestamp: time.Now().UnixNano() / 1e6, Data: data, Pointer: origin})
	}
	conn.SentPacketHandler = func(data []byte, origin unsafe.Pointer) {
		t.Stream = append(t.Stream, TracePacket{Direction: ToServer, Timestamp: time.Now().UnixNano() / 1e6, Data: data, Pointer: origin})
	}
}

func (t *Trace) Complete(conn *Connection) {
	if len(t.ClientRandom) == 0 {
		t.ClientRandom = conn.Tls.ClientRandom()
	}
	if t.Secrets == nil {
		t.Secrets = make(map[pigotls.Epoch]Secrets)
	}
	if _, ok := t.Secrets[pigotls.Epoch0RTT]; !ok && len(conn.Tls.ZeroRTTSecret()) > 0 {
		t.Secrets[pigotls.Epoch0RTT] = Secrets{Epoch: pigotls.Epoch0RTT, Write: conn.Tls.ZeroRTTSecret()}
	}
	if _, ok := t.Secrets[pigotls.EpochHandshake]; !ok && len(conn.Tls.HandshakeReadSecret()) > 0 || len(conn.Tls.HandshakeWriteSecret()) > 0 {
		t.Secrets[pigotls.EpochHandshake] = Secrets{Epoch: pigotls.EpochHandshake, Read: conn.Tls.HandshakeReadSecret(), Write: conn.Tls.HandshakeWriteSecret()}
	}
	if _, ok := t.Secrets[pigotls.Epoch1RTT]; !ok && len(conn.Tls.ProtectedReadSecret()) > 0 || len(conn.Tls.ProtectedWriteSecret()) > 0 {
		t.Secrets[pigotls.Epoch1RTT] = Secrets{Epoch: pigotls.Epoch1RTT, Read: conn.Tls.ProtectedReadSecret(), Write: conn.Tls.ProtectedWriteSecret()}
	}
}

type Direction string

const ToServer Direction = "to_server"
const ToClient Direction = "to_client"

type TracePacket struct {
	Direction    Direction      `json:"direction"`
	Timestamp    int64          `json:"timestamp"`
	Data         []byte         `json:"data"`
	IsOfInterest bool           `json:"is_of_interest"`
	Pointer      unsafe.Pointer `json:"-"`
}

func GitCommit() string {
	var (
		cmdOut []byte
		err    error
	)
	cmdName := "git"
	cmdArgs := []string{"rev-parse", "--verify", "HEAD"}
	if cmdOut, err = exec.Command(cmdName, cmdArgs...).Output(); err != nil {
		return ""
	}
	return strings.TrimSpace(string(cmdOut))
}