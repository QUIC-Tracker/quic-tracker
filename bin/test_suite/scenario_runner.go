package main

import (
	"encoding/json"
	"flag"
	qt "github.com/QUIC-Tracker/quic-tracker"
	s "github.com/QUIC-Tracker/quic-tracker/scenarii"
	"os"
	"os/exec"
	"strings"
	"time"
)

func main() {
	host := flag.String("host", "", "The host endpoint to run the test against.")
	path := flag.String("path", "/index.html", "The path to request when performing tests that needs data to be sent.")
	alpn := flag.String("alpn", "hq", "The ALPN prefix to use when connecting ot the endpoint.")
	scenarioName := flag.String("scenario", "", "The particular scenario to run.")
	outputFile := flag.String("output", "", "The file to write the output to. Output to stdout if not set.")
	qlog := flag.String("qlog", "", "The file to write the qlog output to.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	nopcap := flag.Bool("nopcap", false, "Disables the pcap capture.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap.")
	timeout := flag.Int("timeout", 10, "The amount of time in seconds spent when completing the test. Defaults to 10. When set to 0, the test ends as soon as possible.")
	flag.Parse()

	if *host == "" || *path == "" || *scenarioName == "" {
		println("Parameters host, path and scenario are required")
		os.Exit(-1)
	}

	scenario, ok := s.GetAllScenarii()[*scenarioName]
	if !ok {
		println("Unknown scenario", *scenarioName)
		return
	}

	trace := qt.NewTrace(scenario.Name(), scenario.Version(), *host)

	conn, err := qt.NewDefaultConnection(*host, strings.Split(*host, ":")[0], nil, scenario.IPv6(), *alpn, scenario.HTTP3()) // Raw IPv6 are not handled correctly

	if err == nil {
		conn.QLog.Title = "QUIC-Tracker scenario " + *scenarioName

		var pcap *exec.Cmd
		if !*nopcap {
			pcap, err = qt.StartPcapCapture(conn, *netInterface)
			if err != nil {
				trace.Results["pcap_start_error"] = err.Error()
			}
		}

		trace.AttachTo(conn)

		start := time.Now()
		scenario.SetTimer(time.Duration(*timeout) * time.Second)
		scenario.Run(conn, trace, *path, *debug)
		trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
		ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
		trace.Ip = ip[:strings.LastIndex(ip, ":")]
		trace.StartedAt = start.Unix()

		trace.Complete(conn)
		conn.Close()
		if pcap != nil {
			err = trace.AddPcap(conn, pcap)
		}
		if err != nil {
			trace.Results["pcap_completed_error"] = err.Error()
		}

		conn.QLogTrace.Sort()
		trace.QLog = conn.QLog
		if *qlog != "" {
			outFile, err := os.OpenFile(*qlog, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
			if err == nil {
				content, err := json.Marshal(conn.QLog)
				if err == nil {
					outFile.Write(content)
					outFile.Close()
				}
			}
		}
	} else {
		trace.ErrorCode = 255
		trace.Results["udp_error"] = err.Error()
	}

	out, _ := json.Marshal(trace)
	if *outputFile != "" {
		os.Remove(*outputFile)
		outFile, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY, 0755)
		if err == nil {
			outFile.Write(out)
			outFile.Close()
		} else {
			println(err.Error())
		}
	} else {
		println(string(out))
	}

}
