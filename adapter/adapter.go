package adapter

import (
	"encoding/json"
	"fmt"
	qt "github.com/tiferrei/quic-tracker"
	"github.com/tiferrei/quic-tracker/agents"
	tcp "github.com/tiferrei/tcp_server"
	"log"
	"os"
	"sort"
	"strings"
	"time"
)

type Adapter struct {
	connection                *qt.Connection
	trace                     *qt.Trace
	agents                    *agents.ConnectionAgents
	server                    *tcp.Server
	stop                      chan bool
	Logger                    *log.Logger

	incomingLearnerSymbols    qt.Broadcaster // Type: AbstractSymbol
	incomingSulPackets        chan interface{}
	outgoingResponse          Response
}

func NewAdapter(adapterAddress string, sulAddress string, sulName string) (*Adapter, error) {
	adapter := new(Adapter)

	adapter.incomingLearnerSymbols = qt.NewBroadcaster(1000)
	adapter.stop = make(chan bool, 1)
	adapter.Logger = log.New(os.Stderr, "[ADAPTER] ", log.Lshortfile)
	adapter.server = tcp.New(adapterAddress)

	adapter.connection, _ = qt.NewDefaultConnection(sulAddress, sulName, nil, false, "hq", false)
	adapter.incomingSulPackets = adapter.connection.IncomingPackets.RegisterNewChan(1000)

	adapter.trace = qt.NewTrace("Adapter", 1, sulAddress)
	adapter.trace.AttachTo(adapter.connection)
	adapter.trace.StartedAt = time.Now().Unix()
	ip := strings.Replace(adapter.connection.ConnectedIp().String(), "[", "", -1)
	adapter.trace.Ip = ip[:strings.LastIndex(ip, ":")]

	adapter.agents = agents.AttachAgentsToConnection(adapter.connection, agents.GetBasicAgents()...)
	adapter.agents.Get("ClosingAgent").(*agents.ClosingAgent).WaitForFirstPacket = true
	adapter.agents.Add(&agents.HandshakeAgent{
		TLSAgent: adapter.agents.Get("TLSAgent").(*agents.TLSAgent),
		SocketAgent: adapter.agents.Get("SocketAgent").(*agents.SocketAgent),
		DisableFrameSending: true,
	})
	adapter.agents.Get("SendingAgent").(*agents.SendingAgent).FrameProducer = adapter.agents.GetFrameProducingAgents()
	adapter.agents.Get("TLSAgent").(*agents.TLSAgent).DisableFrameSending = true
	adapter.agents.Get("AckAgent").(*agents.AckAgent).DisableAcks = map[qt.PNSpace]bool {
		qt.PNSpaceNoSpace: true,
		qt.PNSpaceInitial: true,
		qt.PNSpaceHandshake: true,
		qt.PNSpaceAppData: true,
	}

	adapter.server.OnNewMessage(adapter.handleNewServerInput)


	return adapter, nil
}

func (a *Adapter) Run() {
	go a.server.Listen()
	a.Logger.Printf("Server now listening.")
	incomingSymbolChannel := a.incomingLearnerSymbols.RegisterNewChan(1000)

	for {
		select {
		case i := <-incomingSymbolChannel:
			as := i.(AbstractSymbol)
			pnSpace := qt.PacketTypeToPNSpace[as.packetType]
			encLevel := qt.PacketTypeToEncryptionLevel[as.packetType]
			if as.headerOptions.QUICVersion != nil {
				a.connection.Version = *as.headerOptions.QUICVersion
			}
			for _, frameType := range as.frameTypes {
				switch frameType {
				case qt.AckType:
					a.agents.Get("AckAgent").(*agents.AckAgent).SendFromQueue <- pnSpace
				case qt.CryptoType:
					a.agents.Get("TLSAgent").(*agents.TLSAgent).SendFromQueue <- encLevel
				case qt.PaddingFrameType:
					a.connection.FrameQueue.Submit(qt.QueuedFrame{Frame: new(qt.PaddingFrame), EncryptionLevel: encLevel})
				case qt.StreamType:
					a.connection.StreamInput.Submit(qt.StreamInput{StreamId: 0, Data: []byte(fmt.Sprintf("GET %s\r\n", "/index.html"))})
				default:
					panic(fmt.Sprintf("Error: Frame Type '%v' not implemented!", frameType))
				}
			}
			a.Logger.Printf("Submitting request: %v", as.String())
			a.connection.PreparePacket.Submit(encLevel)
		case o := <-a.incomingSulPackets:
			var packetType qt.PacketType
			version := &a.connection.Version
			frameTypes := []qt.FrameType{}

			switch packet := o.(type) {
			case *qt.VersionNegotiationPacket:
				packetType = qt.VersionNegotiation
				version = &packet.Version
			case *qt.RetryPacket:
				packetType = qt.Retry
				version = nil
			case qt.Framer:
				packetType = packet.Header().PacketType()
				// TODO: GetFrames() might not return a deterministic order. Idk yet.
				for _, frame := range packet.GetFrames() {
					if frame.FrameType() != qt.PaddingFrameType {
						// We don't want to pass PADDINGs to the learner.
						frameTypes = append(frameTypes, frame.FrameType())
					}
				}
				// A framer with no frames is a result of removing retransmitted ones.
				// FIXME: This could be more elegant.
				if len(frameTypes) == 0 {
					continue
				}
			default:
				panic(fmt.Sprintf("Error: Packet '%T' not implemented!", packet))
			}

			abstractSymbol := NewAbstractSymbol(
				packetType,
				HeaderOptions{QUICVersion: version},
				frameTypes)
			a.Logger.Printf("Got response: %v", abstractSymbol.String())
			a.outgoingResponse = append(a.outgoingResponse, abstractSymbol)
		case <-a.stop:
			return
		default:
			// Got nothing this time...
		}
	}
}

func (a *Adapter) Stop() {
	a.trace.Complete(a.connection)
	a.agents.StopAll()
	a.SaveTrace("trace.json")
	a.agents.CloseConnection(false, 0, "")
	a.stop <- true
}

func (a *Adapter) Reset() {
	a.Logger.Print("Received RESET command.")
	a.connection.ConnectionRestart <- true
	a.incomingSulPackets = a.connection.IncomingPackets.RegisterNewChan(1000)
}

func (a *Adapter) handleNewServerInput(client *tcp.Client, message string) {
	message = strings.TrimSuffix(message, "\n")
	message = strings.TrimSuffix(message, "\r")
	query := strings.Split(message, " ")
	a.Logger.Printf("Server input: %v", query)
	if len(query) == 1 {
		switch query[0] {
		case "START":
			go a.Run()
		case "RESET":
			a.Reset()
		case "STOP":
			a.Stop()
			_ = client.Close()
		default:
			a.handleNewAbstractQuery(client, query)
		}
	} else {
		a.handleNewAbstractQuery(client, query)
	}
}

func (a *Adapter) handleNewAbstractQuery(client *tcp.Client, query []string) {
	queryAnswer := []string{}
	for _, message := range query {
		a.outgoingResponse = nil
		abstractSymbol := NewAbstractSymbolFromString(message)
		a.incomingLearnerSymbols.Submit(abstractSymbol)
		time.Sleep(200 * time.Millisecond)
		sort.Slice(a.outgoingResponse, func(i, j int) bool {
			return a.outgoingResponse[i].String() > a.outgoingResponse[j].String()
		})
		queryAnswer = append(queryAnswer, a.outgoingResponse.String())
		a.outgoingResponse = nil
	}

	err := client.Send(strings.Join(queryAnswer, " ") + "\n")
	if err != nil {
		fmt.Printf(err.Error())
	}
}

func (a *Adapter) SaveTrace(filename string) {
	a.connection.QLog.Title = "QUIC Adapter Trace"
	a.connection.QLogTrace.Sort()
	a.trace.QLog = a.connection.QLog
	outFile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err == nil {
		content, err := json.Marshal(a.trace)
		if err == nil {
			outFile.Write(content)
			outFile.Close()
		}
	}
}
