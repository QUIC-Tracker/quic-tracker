package main

import (
	"flag"
	"os"
	"sort"
	"github.com/QUIC-Tracker/quic-tracker/scenarii"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"bufio"
	"strings"
	"os/exec"
	"runtime"
	"path"
	"io/ioutil"
	"fmt"
	"sync"
	"encoding/json"
	"time"
)

func main() {
	hostsFilename := flag.String("hosts", "", "A tab-separated file containing hosts and the URLs used to request data to be sent.")
	scenarioName := flag.String("scenario", "", "A particular scenario to run. Run all of them if the parameter is missing.")
	outputFilename := flag.String("output", "", "The file to write the output to. Output to stdout if not set.")
	logsDirectory := flag.String("logs-directory", "/tmp", "Location of the logs.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcaps. Lets tcpdump decide if not set.")
	parallel := flag.Bool("parallel", false, "Runs each scenario against multiple hosts at the same time.")
	maxInstances := flag.Int("max-instances", 10, "Limits the number of parallel scenario runs.")
	randomise := flag.Bool("randomise", false, "Randomise the execution order of scenarii")
	timeout := flag.Int("timeout", 10, "The amount of time in seconds spent when completing a test. Defaults to 10. When set to 0, each test ends as soon as possible.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	flag.Parse()

	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		println("No caller information")
		os.Exit(-1)
	}
	scenarioRunnerFilename := path.Join(path.Dir(filename), "scenario_runner.go")

	if *hostsFilename == "" {
		println("The hosts parameter is required")
		os.Exit(-1)
	}

	file, err := os.Open(*hostsFilename)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	scenariiInstances := scenarii.GetAllScenarii()

	var scenarioIds []string
	for scenarioId := range scenariiInstances {
		scenarioIds = append(scenarioIds, scenarioId)
	}
	if !*randomise {
		sort.Strings(scenarioIds)
	}

	if *scenarioName != "" && scenariiInstances[*scenarioName] == nil {
		println("Unknown scenario", *scenarioName)
	}

	var results Results
	result := make(chan *qt.Trace)
	resultsAgg := make(chan bool)

	go func() {
		for t := range result {
			results = append(results, *t)
		}
		close(resultsAgg)
	}()

	for _, id := range scenarioIds {
		if *scenarioName != "" && *scenarioName != id {
			continue
		}
		scenario := scenariiInstances[id]

		if !*parallel {
			*maxInstances = 1
		}
		semaphore := make(chan bool, *maxInstances)
		for i := 0; i < *maxInstances; i++ {
			semaphore <- true
		}
		wg := &sync.WaitGroup{}

		os.MkdirAll(path.Join(*logsDirectory, id), os.ModePerm)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := strings.Split(scanner.Text(), "\t")
			host, url := line[0], line[1]

			<-semaphore
			wg.Add(1)
			if *debug {
				fmt.Println("starting", scenario.Name(), "against", host)
			}

			go func() {
				defer func() { semaphore <- true }()
				defer wg.Done()

				outputFile, err := ioutil.TempFile("", "quic_tracker")
				if err != nil {
					println(err.Error())
					return
				}
				outputFile.Close()

				logFile, err := os.Create(path.Join(*logsDirectory, id, host))
				if err != nil {
					println(err.Error())
					return
				}
				defer logFile.Close()

				crashTrace := GetCrashTrace(scenario, host) // Prepare one just in case
				start := time.Now()

				args := []string{"run", scenarioRunnerFilename, "-host", host, "-url", url, "-scenario", id, "-interface", *netInterface, "-output", outputFile.Name(), "-timeout", string(*timeout)}
				if *debug {
					args = append(args, "-debug")
				}

				c := exec.Command("go", args...)
				c.Stdout = logFile
				c.Stderr = logFile
				err = c.Run()
				if err != nil {
					println(err.Error())
				}

				var trace qt.Trace
				outputFile, err = os.Open(outputFile.Name())
				if err != nil {
					println(err)
				}
				defer outputFile.Close()
				defer os.Remove(outputFile.Name())

				err = json.NewDecoder(outputFile).Decode(&trace)
				if err != nil {
					println(err.Error())
					crashTrace.StartedAt = start.Unix()
					crashTrace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
					result <- crashTrace
					return
				}
				result <- &trace
			}()
		}

		wg.Wait()
		file.Seek(0, 0)
	}
	close(result)
	<-resultsAgg

	sort.Sort(results)
	out, _ := json.Marshal(results)
	if *outputFilename != "" {
		outFile, err := os.Create(*outputFilename)
		defer outFile.Close()
		if err == nil {
			outFile.Write(out)
			return
		} else {
			println(err.Error())
		}
	}

	println(string(out))
}

func GetCrashTrace(scenario scenarii.Scenario, host string) *qt.Trace {
	trace := qt.NewTrace(scenario.Name(), scenario.Version(), host)
	trace.ErrorCode = 254
	return trace
}

type Results []qt.Trace
func (a Results) Less(i, j int) bool {
	if a[i].Scenario == a[j].Scenario {
		return a[i].Host < a[j].Host
	}
	return a[i].Scenario < a[j].Scenario
}
func (a Results) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Results) Len() int           { return len(a) }