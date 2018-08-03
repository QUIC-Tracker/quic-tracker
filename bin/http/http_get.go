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
	"github.com/davecgh/go-spew/spew"
	m "github.com/mpiraux/master-thesis"
	"flag"
	"strings"
	"fmt"
	"io/ioutil"
	"os"
	"encoding/json"
	"github.com/mpiraux/master-thesis/scenarii"
	"log"
	"net/http"
	_ "net/http/pprof"
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
	conn.DisableRetransmits = true
	pcap, err := m.StartPcapCapture(conn, *netInterface)
	if err != nil {
		panic(err)
	}
	defer func() {
		pcap, err := m.StopPcapCapture(pcap)
		if err == nil {
			ioutil.WriteFile("/tmp/http_get.pcap", pcap, os.ModePerm)
		}
	}()

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

	if scenarii.CompleteHandshake(conn); err != nil {
		spew.Dump(err)
		return
	}

	streamFrame := m.NewStreamFrame(4, conn.Streams.Get(4), []byte(fmt.Sprintf("GET %s\r\n", *url)), true)
	ackFrame := conn.GetAckFrame(m.PNSpaceAppData)

	protectedPacket := m.NewProtectedPacket(conn)
	protectedPacket.AddFrame(streamFrame)
	if ackFrame != nil {
		protectedPacket.AddFrame(ackFrame)
	}
	conn.SendProtectedPacket(protectedPacket)

	for p := range conn.IncomingPackets {
		if p.ShouldBeAcknowledged() {
			pp := m.NewProtectedPacket(conn)
			pp.Frames = append(pp.Frames, conn.GetAckFrame(p.PNSpace()))
			conn.SendProtectedPacket(pp)
		}

		if conn.Streams.Get(4).ReadClosed {
			spew.Dump(conn.Streams.Get(4).ReadData)
			break
		}
	}

	conn.CloseConnection(false, 0, "")
}