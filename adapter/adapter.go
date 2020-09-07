package adapter

import (
	"encoding/json"
	"fmt"
	mapset "github.com/deckarep/golang-set"
	qt "github.com/tiferrei/quic-tracker"
	"github.com/tiferrei/quic-tracker/agents"
	tcp "github.com/tiferrei/tcp_server"
	"log"
	"os"
	"strings"
	"time"
)

type Adapter struct {
	connection                *qt.Connection
	http3                     bool
	trace                     *qt.Trace
	agents                    *agents.ConnectionAgents
	server                    *tcp.Server
	stop                      chan bool
	Logger                    *log.Logger

	incomingLearnerSymbols qt.Broadcaster // Type: AbstractSymbol
	incomingSulPackets     chan interface{}
	outgoingSulPackets     chan interface{}
	outgoingPacket         *ConcreteSymbol
	incomingPacketSet      ConcreteSet
	outgoingResponse       AbstractSet
	oracleTable            AbstractConcreteMap
}

func NewAdapter(adapterAddress string, sulAddress string, sulName string, http3 bool) (*Adapter, error) {
	adapter := new(Adapter)

	adapter.incomingLearnerSymbols = qt.NewBroadcaster(1000)
	adapter.http3 = http3
	adapter.stop = make(chan bool, 1)
	adapter.Logger = log.New(os.Stderr, "[ADAPTER] ", log.Lshortfile)
	adapter.server = tcp.New(adapterAddress)

	adapter.connection, _ = qt.NewDefaultConnection(sulAddress, sulName, nil, false, "hq", adapter.http3)
	adapter.incomingSulPackets = adapter.connection.IncomingPackets.RegisterNewChan(1000)
	adapter.outgoingSulPackets = adapter.connection.OutgoingPackets.RegisterNewChan(1000)

	adapter.outgoingPacket = nil
	adapter.incomingPacketSet = *NewConcreteSet()
	adapter.outgoingResponse = *NewAbstractSet()
	adapter.oracleTable = *NewAbstractConcreteMap()

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
	adapter.agents.Get("StreamAgent").(*agents.StreamAgent).DisableFrameSending = true
	if adapter.http3 {
		adapter.agents.Add(&agents.HTTP3Agent{})
	} else {
		adapter.agents.Add(&agents.HTTP09Agent{})
	}
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
			pnSpace := qt.PacketTypeToPNSpace[as.PacketType]
			encLevel := qt.PacketTypeToEncryptionLevel[as.PacketType]
			if as.HeaderOptions.QUICVersion != nil {
				a.connection.Version = *as.HeaderOptions.QUICVersion
			}
			frameTypesSlice := []qt.FrameType{}
			for _, frameType := range as.FrameTypes.ToSlice() {
				frameTypesSlice = append(frameTypesSlice, frameType.(qt.FrameType))
			}
			for _, frameType := range frameTypesSlice {
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
					if len(a.connection.StreamQueue[qt.FrameRequest{FrameType: qt.StreamType, EncryptionLevel: qt.EncryptionLevel1RTT}]) == 0 {
						if a.http3 {
							a.agents.Get("HTTP3Agent").(*agents.HTTP3Agent).SendRequest("/index.html", "GET", a.connection.Host.String(), nil)
						} else {
							a.agents.Get("HTTP09Agent").(*agents.HTTP09Agent).SendRequest("/index.html", "GET", a.connection.Host.String(), nil)
						}
                        // FIXME: This ensures the request gets queued before packets are sent. I'm not proud of it but it works.
                        time.Sleep(1 * time.Millisecond)
					}
					a.agents.Get("StreamAgent").(*agents.StreamAgent).SendFromQueue <- qt.FrameRequest{qt.StreamType, encLevel}
				case qt.MaxDataType:
				case qt.MaxStreamDataType:
					a.agents.Get("FlowControlAgent").(*agents.FlowControlAgent).SendFromQueue <- qt.FrameRequest{qt.MaxStreamDataType, encLevel}
				default:
					panic(fmt.Sprintf("Error: Frame Type '%v' not implemented!", frameType))
				}
			}
			a.Logger.Printf("Submitting request: %v", as.String())
			a.connection.PreparePacket.Submit(encLevel)
		case o := <-a.incomingSulPackets:
			var packetType qt.PacketType
			version := &a.connection.Version
			frameTypes := mapset.NewSet()

			switch packet := o.(type) {
			case *qt.VersionNegotiationPacket:
				packetType = qt.VersionNegotiation
				version = &packet.Version
			case *qt.RetryPacket:
				packetType = qt.Retry
				version = nil
			case qt.Framer:
				packetType = packet.GetHeader().GetPacketType()
				// TODO: GetFrames() might not return a deterministic order. Idk yet.
				for _, frame := range packet.GetFrames() {
					if frame.FrameType() != qt.PaddingFrameType {
						// We don't want to pass PADDINGs to the learner.
						frameTypes.Add(frame.FrameType())
					}
				}
				// A framer with no frames is a result of removing retransmitted ones.
				// FIXME: This could be more elegant.
				if frameTypes.Cardinality() == 0 {
					continue
				}
			default:
				panic(fmt.Sprintf("Error: Packet '%T' not implemented!", packet))
			}

			a.incomingPacketSet.Add(NewConcreteSymbol(o))
			abstractSymbol := NewAbstractSymbol(
				packetType,
				HeaderOptions{QUICVersion: version},
				frameTypes)
			a.Logger.Printf("Got response: %v", abstractSymbol.String())
			a.outgoingResponse.Add(abstractSymbol)
		case o := <- a.outgoingSulPackets:
			cs := NewConcreteSymbol(o)
			a.outgoingPacket = &cs
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
	a.SaveOracleTable("oracleTable.json")
	a.agents.Stop("SendingAgent")
	a.agents.StopAll()
	a.stop <- true
}

func (a *Adapter) Reset(client *tcp.Client) {
	a.Logger.Print("Received RESET command")
	a.agents.Stop("SendingAgent")
	a.agents.StopAll()
	a.connection.Close()
	a.connection, _ = qt.NewDefaultConnection(a.connection.ConnectedIp().String(), a.connection.ServerName, nil, false, "hq", a.http3)
	a.incomingSulPackets = a.connection.IncomingPackets.RegisterNewChan(1000)
	a.outgoingSulPackets = a.connection.OutgoingPackets.RegisterNewChan(1000)
	a.outgoingPacket = nil
	a.incomingPacketSet = *NewConcreteSet()
	a.outgoingResponse = *NewAbstractSet()
	a.trace.AttachTo(a.connection)
	a.agents = agents.AttachAgentsToConnection(a.connection, agents.GetBasicAgents()...)
	a.agents.Get("ClosingAgent").(*agents.ClosingAgent).WaitForFirstPacket = true
	a.agents.Add(&agents.HandshakeAgent{
		TLSAgent: a.agents.Get("TLSAgent").(*agents.TLSAgent),
		SocketAgent: a.agents.Get("SocketAgent").(*agents.SocketAgent),
		DisableFrameSending: true,
	})
	a.agents.Add(&agents.SendingAgent{
		MTU: 1200,
		FrameProducer: a.agents.GetFrameProducingAgents(),
	})
	a.agents.Get("StreamAgent").(*agents.StreamAgent).DisableFrameSending = true
	if a.http3 {
		a.agents.Add(&agents.HTTP3Agent{})
	} else {
		a.agents.Add(&agents.HTTP09Agent{})
	}
	a.agents.Get("SendingAgent").(*agents.SendingAgent).KeepDroppedEncryptionLevels = true
	a.agents.Get("FlowControlAgent").(*agents.FlowControlAgent).DisableFrameSending = true
	a.agents.Get("TLSAgent").(*agents.TLSAgent).DisableFrameSending = true
	a.agents.Get("AckAgent").(*agents.AckAgent).DisableAcks = map[qt.PNSpace]bool {
		qt.PNSpaceNoSpace: true,
		qt.PNSpaceInitial: true,
		qt.PNSpaceHandshake: true,
		qt.PNSpaceAppData: true,
	}

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
			os.Exit(0)
		default:
			a.handleNewAbstractQuery(client, query, waitTime)
		}
	} else {
		a.handleNewAbstractQuery(client, query, waitTime)
	}
}

func (a *Adapter) handleNewAbstractQuery(client *tcp.Client, query []string, waitTime time.Duration) {
	abstractInputs := []AbstractSymbol{}
	abstractOutputs := []AbstractSet{}
	concreteInputs := []*ConcreteSymbol{}
	concreteOutputs := []ConcreteSet{}
	for _, message := range query {
		a.outgoingResponse.Clear()
		a.incomingPacketSet.Clear()
		a.outgoingPacket = nil
		abstractSymbol := NewAbstractSymbolFromString(message)
		abstractInputs = append(abstractInputs, abstractSymbol)

		// If there we don't have the requested encryption level, skip and return EMPTY.
		if a.connection.CryptoState(qt.PacketTypeToEncryptionLevel[abstractSymbol.PacketType]) != nil {
			a.incomingLearnerSymbols.Submit(abstractSymbol)
			time.Sleep(waitTime)
		} else {
			a.Logger.Printf("Unable to send packet at " + qt.PacketTypeToEncryptionLevel[abstractSymbol.PacketType].String() + " EL.")
		}

		abstractOutputs = append(abstractOutputs, a.outgoingResponse)
		concreteInputs = append(concreteInputs, a.outgoingPacket)
		concreteOutputs = append(concreteOutputs, a.incomingPacketSet)

		// If we received a Retry, give the connection time to restart.
		if strings.Contains(a.outgoingResponse.String(), "RETRY") {
			time.Sleep(300 * time.Millisecond)
		}
	}

	a.oracleTable.AddIOs(abstractInputs, abstractOutputs, concreteInputs, concreteOutputs)

	aoStringSlice := []string{}
	for _, value := range abstractOutputs {
		aoStringSlice = append(aoStringSlice, value.String())
	}

	err := client.Send(strings.Join(aoStringSlice, " ") + "\n")
	if err != nil {
		fmt.Printf(err.Error())
	}
}

func writeJson(filename string, object interface{}) {
	outFile, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err == nil {
		content, err := json.Marshal(object)
		if err == nil {
			outFile.Write(content)
			outFile.Close()
		}
	}
}

func (a *Adapter) SaveTrace(filename string) {
	a.connection.QLog.Title = "QUIC Adapter Trace"
	a.connection.QLogTrace.Sort()
	a.trace.QLog = a.connection.QLog
	writeJson(filename, a.trace)
}

func (a *Adapter) SaveOracleTable(filename string) {
	writeJson(filename, a.oracleTable)
}
