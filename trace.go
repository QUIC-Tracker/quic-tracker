/*
    Maxime Piraux's master's thesis
    Copyright (C) 2017-2018  Maxime Piraux

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
	as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/
package masterthesis

import (
	"os/exec"
	"time"
	"strings"
	"unsafe"
)

type Trace struct {
	Commit              string                 `json:"commit"`
	Scenario            string                 `json:"scenario"`
	ScenarioVersion     int                    `json:"scenario_version"`
	Host                string                 `json:"host"`
	Ip                  string                 `json:"ip"`
	Results             map[string]interface{} `json:"results"`
	StartedAt           int64                  `json:"started_at"`
	Duration            uint64                 `json:"duration"`
	ErrorCode           uint8                  `json:"error_code"`
	Stream              []TracePacket          `json:"stream"`
	Pcap                []byte                 `json:"pcap"`
	DecryptedPcap       []byte                 `json:"decrypted_pcap"`
	ClientRandom        []byte                 `json:"client_random"`
	ExporterSecret      []byte                 `json:"exporter_secret"`
	EarlyExporterSecret []byte                 `json:"early_exporter_secret"`
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

func (t *Trace) AddPcap(c *exec.Cmd) error {
	content, err := StopPcapCapture(c)
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
	t.ClientRandom = conn.ClientRandom
	t.ExporterSecret = conn.ExporterSecret
	t.EarlyExporterSecret = conn.Tls.EarlyExporterSecret()
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
		panic(err)
	}
	return strings.TrimSpace(string(cmdOut))
}