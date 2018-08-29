package main

import (
	m "github.com/QUIC-Tracker/quic-tracker"
	"flag"
	"strings"
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"github.com/QUIC-Tracker/quic-tracker/agents"
	"github.com/davecgh/go-spew/spew"
	"time"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	address := flag.String("address", "", "The address to connect to")
	useIPv6 := flag.Bool("6", false, "Use IPV6")
	url := flag.String("url", "/index.html", "The URL to request")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap")
	timeout := flag.Int("timeout", 10, "The number of seconds after which the program will timeout")
	flag.Parse()

	t := time.NewTimer(time.Duration(*timeout) * time.Second)
	conn, err := m.NewDefaultConnection(*address, (*address)[:strings.LastIndex(*address, ":")], nil, *useIPv6)
	if err != nil {
		panic(err)
	}

	pcap, err := m.StartPcapCapture(conn, *netInterface)
	if err != nil {
		panic(err)
	}

	trace := m.NewTrace("http_get", 1, *address)
	trace.AttachTo(conn)
	defer func() {
		trace.Complete(conn)
		err = trace.AddPcap(conn, pcap)
		if err != nil {
			trace.Results["pcap_error"] = err.Error()
		}

		var t []m.Trace
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

	defer conn.CloseConnection(false, 0, "")
	conn.FrameQueue.Submit(m.QueuedFrame{m.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", *url)), true), m.EncryptionLevel1RTT})

	incomingPackets := make(chan interface{}, 1000)
	conn.IncomingPackets.Register(incomingPackets)

	for {
		select {
		case <-incomingPackets:
			if conn.Streams.Get(4).ReadClosed {
				spew.Dump(conn.Streams.Get(4).ReadData)
				break
			}
		case <-t.C:
			return
		}

	}

}
