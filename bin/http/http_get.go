package main

import (
	"encoding/json"
	"flag"
	"fmt"
	qt "github.com/QUIC-Tracker/quic-tracker"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"github.com/davecgh/go-spew/spew"
	"log"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strings"
	"time"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	address := flag.String("address", "", "The address to connect to")
	useIPv6 := flag.Bool("6", false, "Use IPV6")
	path := flag.String("path", "/index.html", "The path to request")
	alpn := flag.String("alpn", "hq", "The ALPN prefix to use when connecting ot the endpoint.")
	qlog := flag.String("qlog", "", "The file to write the qlog output to.")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap")
	timeout := flag.Int("timeout", 10, "The number of seconds after which the program will timeout")
	h3 := flag.Bool("3", false, "Use HTTP/3 instead of HTTP/0.9")
	flag.Parse()

	t := time.NewTimer(time.Duration(*timeout) * time.Second)
	conn, err := qt.NewDefaultConnection(*address, (*address)[:strings.LastIndex(*address, ":")], nil, *useIPv6, *alpn, *h3)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	conn.QLog.Title = fmt.Sprintf("QUIC-Tracker HTTP GET %s%s", *address, *path)

	if *h3 {
		conn.TLSTPHandler.MaxUniStreams = 3
	}

	pcap, err := qt.StartPcapCapture(conn, *netInterface)
	if err != nil {
		panic(err)
	}

	trace := qt.NewTrace("http_get", 1, *address)
	trace.AttachTo(conn)
	defer func() {
		trace.Complete(conn)
		err = trace.AddPcap(conn, pcap)
		if err != nil {
			trace.Results["pcap_error"] = err.Error()
		}

		var t []qt.Trace
		t = append(t, *trace)
		out, err := json.Marshal(t)
		if err != nil {
			println(err)
		}
		println(string(out))
	}()

	Agents := agents.AttachAgentsToConnection(conn, agents.GetDefaultAgents()...)
	handshakeAgent := &agents.HandshakeAgent{TLSAgent: Agents.Get("TLSAgent").(*agents.TLSAgent), SocketAgent: Agents.Get("SocketAgent").(*agents.SocketAgent)}
	Agents.Add(handshakeAgent)
	Agents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = Agents.GetFrameProducingAgents()

	handshakeStatus := make(chan interface{}, 10)
	handshakeAgent.HandshakeStatus.Register(handshakeStatus)
	handshakeAgent.InitiateHandshake()

	select {
	case i := <-handshakeStatus:
		s := i.(agents.HandshakeStatus)
		if !s.Completed {
			Agents.StopAll()
			return
		}
	case <-t.C:
		Agents.StopAll()
		return
	}

	defer func() {
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
	}()
	defer conn.CloseConnection(false, 0, "")

	var httpAgent agents.HTTPAgent

	if !*h3 {
		httpAgent = &agents.HTTP09Agent{}
	} else {
		httpAgent = &agents.HTTP3Agent{}
	}
	Agents.Add(httpAgent)

	select {
	case r := <-httpAgent.SendRequest(*path, "GET", trace.Host, nil):
		spew.Dump(r)
	case <-t.C:
		return
	}
}
