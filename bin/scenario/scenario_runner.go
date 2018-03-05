package main

import (
	"os"
	"bufio"
	m "masterthesis"
	s "masterthesis/scenarii"
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
	defer file.Close()

	commit := GitCommit()

	scenarii := [...]s.Scenario{s.NewFlowControlScenario(),/*s.NewVersionNegotationScenario(),
								s.NewHandshakeScenario(),
								s.NewHandshakev6Scenario(),
								s.NewTransportParameterScenario(),
								s.NewHandshakeRetransmissionScenario()*/}
	results := make([]m.Trace, 0, 0)

	for _, scenario := range scenarii {
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			host := scanner.Text()
			print(scenario.Name(), " ", host)

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
				scenario.Run(conn, &trace)
				trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
				ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
				trace.Ip = ip[:strings.LastIndex(ip, ":")]
			} else {
				trace.ErrorCode = 255
				trace.Results["udp_error"] = err
			}

			results = append(results, trace)
			println(" ", trace.ErrorCode)
		}
		file.Seek(0, 0)
	}

	out, _ := json.Marshal(results)
	println(string(out))
}
