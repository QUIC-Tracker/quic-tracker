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
	adapter.agents.Add(&agents.SendingAgent{
		MTU: 1200,
		FrameProducer: adapter.agents.GetFrameProducingAgents(),
	})
	adapter.agents.Get("SendingAgent").(*agents.SendingAgent).KeepDroppedEncryptionLevels = true
	adapter.agents.Get("FlowControlAgent").(*agents.FlowControlAgent).DisableFrameSending = true
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
				case qt.PingType:
					a.connection.FrameQueue.Submit(qt.QueuedFrame{Frame: new(qt.PingFrame), EncryptionLevel: encLevel})
				case qt.CryptoType:
					a.agents.Get("TLSAgent").(*agents.TLSAgent).SendFromQueue <- encLevel
				case qt.PaddingFrameType:
					a.connection.FrameQueue.Submit(qt.QueuedFrame{Frame: new(qt.PaddingFrame), EncryptionLevel: encLevel})
				case qt.StreamType:
					a.connection.StreamInput.Submit(qt.StreamInput{StreamId: a.getNextStreamID(), Data: []byte(fmt.Sprintf("GET %s\r\n", "/index.html")), Close: true})
				case qt.MaxDataType:
				case qt.MaxStreamDataType:
					a.agents.Get("FlowControlAgent").(*agents.FlowControlAgent).SendFromQueue <- qt.FrameRequest{frameType, encLevel}
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
	a.SaveTrace("trace.json")
	a.agents.StopAll()
	a.stop <- true
}

func (a *Adapter) Reset(client *tcp.Client) {
	a.Logger.Print("Received RESET command")
	a.agents.StopAll()
	a.connection.Close()
	a.connection, _ = qt.NewDefaultConnection(a.connection.ConnectedIp().String(), a.connection.ServerName, nil, false, "hq", false)
	a.incomingSulPackets = a.connection.IncomingPackets.RegisterNewChan(1000)
	a.trace.AttachTo(a.connection)
	a.agents = agents.AttachAgentsToConnection(a.connection, agents.GetBasicAgents()...)
	a.agents.Get("ClosingAgent").(*agents.ClosingAgent).WaitForFirstPacket = true
	a.agents.Add(&agents.HandshakeAgent{
		TLSAgent: a.agents.Get("TLSAgent").(*agents.TLSAgent),
		SocketAgent: a.agents.Get("SocketAgent").(*agents.SocketAgent),
		DisableFrameSending: true,
	})
	a.agents.Get("FlowControlAgent").(*agents.FlowControlAgent).DisableFrameSending = true
	a.agents.Get("TLSAgent").(*agents.TLSAgent).DisableFrameSending = true
	a.agents.Get("AckAgent").(*agents.AckAgent).DisableAcks = map[qt.PNSpace]bool {
		qt.PNSpaceNoSpace: true,
		qt.PNSpaceInitial: true,
		qt.PNSpaceHandshake: true,
		qt.PNSpaceAppData: true,
	}
	a.agents.Add(&agents.SendingAgent{
		MTU: 1200,
		FrameProducer: a.agents.GetFrameProducingAgents(),
	})
	a.agents.Get("SendingAgent").(*agents.SendingAgent).KeepDroppedEncryptionLevels = true
	a.Logger.Print("Finished RESET mechanism")
	err := client.Send("DONE\n")
	if err != nil {
		fmt.Printf(err.Error())
	}
}

func (a *Adapter) handleNewServerInput(client *tcp.Client, message string) {
	message = strings.TrimSuffix(message, "\n")
	message = strings.TrimSuffix(message, "\r")
	query := strings.Split(message, " ")
	a.Logger.Printf("Server input: %v", query)
	waitTime := 300 * time.Millisecond
	if len(query) == 1 {
		switch query[0] {
		case "START":
			go a.Run()
		case "RESET":
			a.Reset(client)
		case "STOP":
			a.Stop()
			_ = client.Close()
		default:
			a.handleNewAbstractQuery(client, query, waitTime)
		}
	} else {
		a.handleNewAbstractQuery(client, query, waitTime)
	}
}

func (a *Adapter) handleNewAbstractQuery(client *tcp.Client, query []string, waitTime time.Duration) {
	queryAnswer := []string{}
	for _, message := range query {
		a.outgoingResponse = nil
		abstractSymbol := NewAbstractSymbolFromString(message)

		// If there we don't have the requested encryption level, skip and return EMPTY.
		if a.connection.CryptoState(qt.PacketTypeToEncryptionLevel[abstractSymbol.packetType]) != nil {
			a.incomingLearnerSymbols.Submit(abstractSymbol)
			time.Sleep(waitTime)
		} else {
			a.Logger.Printf("Unable to send packet at " + qt.PacketTypeToEncryptionLevel[abstractSymbol.packetType].String() + " EL.")
		}

		sort.Slice(a.outgoingResponse, func(i, j int) bool {
			return a.outgoingResponse[i].String() > a.outgoingResponse[j].String()
		})
		queryAnswer = append(queryAnswer, a.outgoingResponse.String())

		// If we received a Retry, give the connection time to restart.
		if strings.Contains(a.outgoingResponse.String(), "RETRY") {
			time.Sleep(300 * time.Millisecond)
		}
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

// Get next available client-initiated, bidirectional Stream ID.
func (a *Adapter) getNextStreamID() uint64 {
	streamID := uint64(0)
	for {
		stream := a.connection.Streams.Get(streamID)
		if !stream.WriteClosed {
			break
		}
		streamID += 4
	}
	return streamID
}
