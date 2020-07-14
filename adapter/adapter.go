package adapter

import (
	"encoding/json"
	"fmt"
	qt "github.com/tiferrei/quic-tracker"
	"github.com/tiferrei/quic-tracker/agents"
	tcp "github.com/tiferrei/tcp_server"
	"os"
	"strings"
	"time"
)

type Adapter struct {
	connection                *qt.Connection
	trace                     *qt.Trace
	agents                    *agents.ConnectionAgents
	server                    *tcp.Server
	stop                      chan bool

	incomingLearnerSymbols    qt.Broadcaster // Type: AbstractSymbol
	outgoingAdapterSymbols    qt.Broadcaster // Type: AbstractSymbol
}

func NewAdapter(adapterAddress string, sulAddress string, sulName string) (*Adapter, error) {
	adapter := new(Adapter)
	adapter.incomingLearnerSymbols = qt.NewBroadcaster(1000)
	adapter.outgoingAdapterSymbols = qt.NewBroadcaster(1000)
	adapter.stop = make(chan bool, 1)
	adapter.server = tcp.New(adapterAddress)

	var err error
	adapter.connection, err = qt.NewDefaultConnection(sulAddress, sulName, nil, false, "hq", false)
	if err != nil {
		return nil, err
	}

	adapter.trace = qt.NewTrace("Adapter", 1, sulAddress)
	adapter.trace.AttachTo(adapter.connection)
	adapter.trace.StartedAt = time.Now().Unix()
	ip := strings.Replace(adapter.connection.ConnectedIp().String(), "[", "", -1)
	adapter.trace.Ip = ip[:strings.LastIndex(ip, ":")]

	adapter.agents = agents.AttachAgentsToConnection(adapter.connection, agents.GetDefaultAgents()...)
	adapter.agents.Get("ClosingAgent").(*agents.ClosingAgent).WaitForFirstPacket = true
	adapter.agents.Stop("RecoveryAgent")
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
	adapter.agents.Stop("RecoveryAgent")

	adapter.server.OnNewMessage(adapter.handleNewServerInput)

	return adapter, nil
}

func (a *Adapter) Run() {
	go a.server.Listen()
	fmt.Print("Server now listening.")
	incomingSymbolChannel := a.incomingLearnerSymbols.RegisterNewChan(1000)
	outgoingSulPacketChannel := a.connection.IncomingPackets.RegisterNewChan(1000)

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
				default:
					panic(fmt.Sprintf("Error: Frame Type '%v' not implemented!", frameType))
				}
			}
			a.connection.PreparePacket.Submit(encLevel)
		case o := <-outgoingSulPacketChannel:
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
					frameTypes = append(frameTypes, frame.FrameType())
				}
			default:
				panic(fmt.Sprintf("Error: Packet '%T' not implemented!", packet))
			}

			a.outgoingAdapterSymbols.Submit(NewAbstractSymbol(
				packetType,
				HeaderOptions{QUICVersion: version},
				frameTypes))
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
	a.connection.Close()
	a.stop <- true
}

func (a *Adapter) Reset() {
	a.stop = make(chan bool, 1)
	a.connection.TransitionTo(qt.QuicVersion, qt.QuicALPNToken)
}

func (a *Adapter) handleNewServerInput(client *tcp.Client, message string) {
	message = strings.TrimSuffix(message, "\r\n")
	switch message {
	case "START":
		go a.Run()
	case "RESET":
		a.Reset()
	case "STOP":
		a.Stop()
		_ = client.Close()
	default:
		go a.handleNewAbstractInput(client, message)
	}
}

func (a *Adapter) handleNewAbstractInput(client *tcp.Client, message string) {
	abstractSymbol := NewAbstractSymbolFromString(message)
	a.incomingLearnerSymbols.Submit(abstractSymbol)
	outgoingSymbols := a.outgoingAdapterSymbols.RegisterNewChan(1000)
	for {
		select {
		case o := <-outgoingSymbols:
			outgoingSymbol := o.(AbstractSymbol)
			err := client.Send(outgoingSymbol.String() + "\n")
			if err != nil {
				fmt.Printf(err.Error())
			}
			break
		}
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
