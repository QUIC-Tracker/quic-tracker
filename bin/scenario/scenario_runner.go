package main

import (
	"os"
	"bufio"
	m "masterthesis"
	"masterthesis/scenario"
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

	scanner := bufio.NewScanner(file)
	results := make([]m.Trace, 0, 0)
	for scanner.Scan() {
		host := scanner.Text()
		trace := m.Trace{
			Commit:    commit,
			Host:      host,
			StartedAt: time.Now().Unix(),
			Results: make(map[string]interface{}),
		}

		start := time.Now()
		trace.Ip = scenario.RunVersionNegotiationScenario(host, &trace)  // TODO: Find a better way of passing ip
		trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)

		out, _ := json.Marshal(trace)
		println(string(out))

		results = append(results, trace)
	}
}
