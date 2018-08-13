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
	m "github.com/mpiraux/master-thesis"
	s "github.com/mpiraux/master-thesis/scenarii"
	"flag"
	"strings"
	"time"
	"encoding/json"
)

func main() {
	host := flag.String("host", "", "The host endpoint to run the test against.")
	url := flag.String("url", "/index.html", "The URL to request when performing tests that needs data to be sent.")
	scenarioName := flag.String("scenario", "", "The particular scenario to run.")
	outputFile := flag.String("output", "", "The file to write the output to. Output to stdout if not set.")
	debug := flag.Bool("debug", false, "Enables debugging information to be printed.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap.")
	flag.Parse()

	if *host == "" || *url == "" || *scenarioName == "" {
		println("Parameters host, url and scenario are required")
		os.Exit(-1)
	}

	scenario, ok := s.GetAllScenarii()[*scenarioName]
	if !ok {
		println("Unknown scenario", *scenarioName)
	}

	trace := m.NewTrace(scenario.Name(), scenario.Version(), *host)

	conn, err := m.NewDefaultConnection(*host, strings.Split(*host, ":")[0], nil, scenario.IPv6())  // Raw IPv6 are not handled correctly

	if err == nil {
		pcap, err := m.StartPcapCapture(conn, *netInterface)
		if err != nil {
			trace.Results["pcap_start_error"] = err.Error()
		}

		trace.AttachTo(conn)

		start := time.Now()
		scenario.Run(conn, trace, *url, *debug)
		trace.Duration = uint64(time.Now().Sub(start).Seconds() * 1000)
		ip := strings.Replace(conn.ConnectedIp().String(), "[", "", -1)
		trace.Ip = ip[:strings.LastIndex(ip, ":")]
		trace.StartedAt = start.Unix()

		conn.Close()
		trace.Complete(conn)
		err = trace.AddPcap(pcap)
		if err != nil {
			trace.Results["pcap_completed_error"] = err.Error()
		}
		trace.DecryptedPcap, err = m.DecryptPcap(trace)
		if err != nil {
			trace.Results["pcap_decrypt_error"] = err.Error()
		}
	} else {
		trace.ErrorCode = 255
		trace.Results["udp_error"] = err.Error()
	}

	out, _ := json.Marshal(trace)
	if *outputFile != "" {
		os.Remove(*outputFile)
		outFile, err := os.OpenFile(*outputFile, os.O_CREATE|os.O_WRONLY, 0755)
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
