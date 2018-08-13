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
	m "github.com/mpiraux/master-thesis"
	"flag"
	"strings"
	"fmt"
	"encoding/json"
	"log"
	"net/http"
	_ "net/http/pprof"
	"github.com/mpiraux/master-thesis/agents"
	"github.com/davecgh/go-spew/spew"
)

func main() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()

	address := flag.String("address", "", "The address to connect to")
	useIPv6 := flag.Bool("6", false, "Use IPV6")
	url := flag.String("url", "/index.html", "The URL to request")
	netInterface := flag.String("interface", "", "The interface to listen to when capturing pcap")
	flag.Parse()
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
		err = trace.AddPcap(pcap)
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

	s := (<-handshakeStatus).(agents.HandshakeStatus)
	if s.Completed {
		conn.FrameQueue.Submit(m.QueuedFrame{m.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", *url)), true), m.EncryptionLevel1RTT})

		incomingPackets := make(chan interface{}, 1000)
		conn.IncomingPackets.Register(incomingPackets)

		for {
			<-incomingPackets
			if conn.Streams.Get(4).ReadClosed {
				spew.Dump(conn.Streams.Get(4).ReadData)
				break
			}
		}
	}

	conn.CloseConnection(false, 0, "")
}
