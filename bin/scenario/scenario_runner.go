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
	"encoding/json"
	"strings"
)


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

	scenarii := [...]s.Scenario{
		s.NewZeroRTTScenario(),
		s.NewConnectionMigrationScenario(),
		s.NewUnsupportedTLSVersionScenario(),
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
			args := strings.Split(scanner.Text(), "\t")
			host, preferredUrl := args[0], args[1]
			if debug {
				print(scenario.Name(), " ", host)
			}

			trace := m.NewTrace(scenario.Name(), scenario.Version(), host)

			conn, err := m.NewDefaultConnection(host, strings.Split(host, ":")[0], nil, scenario.IPv6())

			if err == nil {
				pcap, err := m.StartPcapCapture(conn)

				trace.AttachTo(conn)

				start := time.Now()
				scenario.Run(conn, trace, preferredUrl, debug)
				trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
				ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
				trace.Ip = ip[:strings.LastIndex(ip, ":")]
				trace.StartedAt = start.Unix()

				trace.ClientRandom = conn.ClientRandom
				trace.ExporterSecret = conn.ExporterSecret
				err = trace.AddPcap(pcap)
				if err != nil {
					trace.Results["pcap_error"] = err.Error()
				}
				trace.DecryptedPcap, err = m.DecryptPcap(trace)
				if err != nil {
					trace.Results["pcap_decrypt_error"] = err.Error()
				}
			} else {
				trace.ErrorCode = 255
				trace.Results["udp_error"] = err.Error()
			}

			if conn != nil {
				conn.Close()
			}
			results = append(results, *trace)
			if debug {
				println(" ", trace.ErrorCode)
			}
		}
		file.Seek(0, 0)
	}

	out, _ := json.Marshal(results)
	println(string(out))
}
