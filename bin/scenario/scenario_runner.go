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
package main

import (
	"os"
	"bufio"
	m "github.com/mpiraux/master-thesis"
	s "github.com/mpiraux/master-thesis/scenarii"
	"time"
	"os/exec"
	"encoding/json"
	"strings"
)

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

func main() {
	file, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	var scenarioName string
	if len(os.Args) > 2 {
		scenarioName = os.Args[2]
	}
	defer file.Close()

	debugSwitch, ok := os.LookupEnv("SCENARIO_RUNNER_DEBUG")
	debug := ok && debugSwitch == "1"

	commit := GitCommit()

	scenarii := [...]s.Scenario{
		s.NewStreamOpeningReorderingScenario(),
		s.NewMultiStreamScenario(),
		s.NewNewConnectionIDScenario(),
		s.NewVersionNegotiationScenario(),
		s.NewHandshakeScenario(),
		s.NewHandshakev6Scenario(),
		s.NewTransportParameterScenario(),
		s.NewHandshakeRetransmissionScenario(),
		s.NewPaddingScenario(),
		s.NewFlowControlScenario(),
		s.NewAckOnlyScenario(),
		s.NewStopSendingOnReceiveStreamScenario(),
		s.NewSimpleGetAndWaitScenario(),
		s.NewGetOnStream2Scenario(),
	}
	results := make([]m.Trace, 0, 0)

	for _, scenario := range scenarii {
		if scenarioName != "" && scenario.Name() != scenarioName {
			continue
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			host := scanner.Text()
			if debug {
				print(scenario.Name(), " ", host)
			}

			trace := m.Trace{
				Scenario: scenario.Name(),
				ScenarioVersion: scenario.Version(),
				Commit:    commit,
				Host:      host,
				StartedAt: time.Now().Unix(),
				Results:   make(map[string]interface{}),
			}

			conn, err := m.NewDefaultConnection(host, strings.Split(host, ":")[0], scenario.IPv6())
			if err == nil {
				conn.ReceivedPacketHandler = func(data []byte) {
					trace.Stream = append(trace.Stream, m.TracePacket{Direction: m.ToClient, Timestamp: time.Now().UnixNano() / 1e6, Data: data})
				}
				conn.SentPacketHandler = func(data []byte) {
					trace.Stream = append(trace.Stream, m.TracePacket{Direction: m.ToServer, Timestamp: time.Now().UnixNano() / 1e6, Data: data})
				}

				start := time.Now()
				scenario.Run(conn, &trace, debug)
				trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
				ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
				trace.Ip = ip[:strings.LastIndex(ip, ":")]
			} else {
				trace.ErrorCode = 255
				trace.Results["udp_error"] = err
			}

			results = append(results, trace)
			if debug {
				println(" ", trace.ErrorCode)
			}
		}
		file.Seek(0, 0)
	}

	out, _ := json.Marshal(results)
	println(string(out))
}
