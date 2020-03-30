//
// This package contains pieces of behaviours that constitutes a QUIC client.
//
// Each agent is responsible for a limited part of the behaviour of a QUIC client. This allows modularity when defining
// test scenarii with specific needs. Each agent is described in its type documentation. For more information on the
// architecture of QUIC-Tracker, please consult the package quictracker documentation.
//
package agents

import (
	"encoding/hex"
	"fmt"
	. "github.com/QUIC-Tracker/quic-tracker"
	"log"
	"os"
	"strings"
	"time"
)

type Agent interface {
	Name() string
	Init(name string, ODCID ConnectionID)
	Run(conn *Connection)
	Stop()
	Restart()
	Join()
}

type RequestFrameArgs struct {
	availableSpace int
	level          EncryptionLevel
	number         PacketNumber
}

// All agents should embed this structure
type BaseAgent struct {
	name   string
	Logger *log.Logger
	close  chan bool  // true if should restart, false otherwise
	closed chan bool
}

func (a *BaseAgent) Name() string { return a.name }

// All agents that embed this structure must call Init() as soon as their Run() method is called
func (a *BaseAgent) Init(name string, ODCID ConnectionID) {
	a.name = name
	a.Logger = log.New(os.Stderr, fmt.Sprintf("[%s/%s] ", hex.EncodeToString(ODCID), a.Name()), log.Lshortfile)
	a.Logger.Println("Agent started")
	a.close = make(chan bool)
	a.closed = make(chan bool)
}

func (a *BaseAgent) Stop() {
	select {
	case <-a.close:
	default:
		close(a.close)
	}
}

func (a *BaseAgent) Restart() {
	select {
	case <-a.close:
	default:
		a.close <- true
	}
}

func (a *BaseAgent) Join() {
	<-a.closed
}

type FrameProducer interface {
	RequestFrames(availableSpace int, level EncryptionLevel, number PacketNumber) ([]Frame, bool)
}

type FrameProducingAgent struct {
	BaseAgent
	conn         *Connection
	requestFrame chan RequestFrameArgs
	frames       chan []Frame
}

func (a *FrameProducingAgent) InitFPA(conn *Connection) {
	a.conn = conn
	a.requestFrame = make(chan RequestFrameArgs)
	a.frames = make(chan []Frame)
}

func (a *FrameProducingAgent) RequestFrames(availableSpace int, level EncryptionLevel, number PacketNumber) ([]Frame, bool) {
	select {
	case a.requestFrame <- RequestFrameArgs{availableSpace, level, number}:
		select {
		case f := <-a.frames:
			return f, true
		}
	case <-a.close:
		return nil, false
	}
}

func (a *FrameProducingAgent) Run(conn *Connection) {}

// Represents a set of agents that are attached to a particular connection
type ConnectionAgents struct {
	conn   *Connection
	agents map[string]Agent
}

func AttachAgentsToConnection(conn *Connection, agents ...Agent) *ConnectionAgents {
	c := ConnectionAgents{conn, make(map[string]Agent)}

	for _, a := range agents {
		c.Add(a)
	}

	go func() {
		for {
			select {
			case <-conn.ConnectionRestart:
				conn.Logger.Printf("Restarting all agents\n")
				for _, a := range agents {
					a.Restart()
					a.Join()
				}
				conn.ConnectionRestart = make(chan bool, 1)
				conn.UdpConnection.Close()
				conn.UdpConnection, _ = EstablishUDPConnection(conn.Host)
				for _, a := range agents {
					a.Run(conn)
				}
				close(conn.ConnectionRestarted)
				conn.Logger.Printf("Restarting all agents: done\n")
			case <-conn.ConnectionClosed:
				return
			}
		}
	}()

	return &c
}

func (c *ConnectionAgents) Add(agent Agent) {
	agent.Run(c.conn)
	c.agents[agent.Name()] = agent
}

func (c *ConnectionAgents) Get(name string) Agent {
	return c.agents[name]
}

func (c *ConnectionAgents) Has(name string) (Agent, bool) {
	a, b := c.agents[name]
	return a, b
}

func (c *ConnectionAgents) GetFrameProducingAgents() []FrameProducer {
	var agents []FrameProducer
	for _, a := range c.agents {
		if fpa, ok := a.(FrameProducer); ok {
			agents = append(agents, fpa)
		}
	}
	return agents
}

func (c *ConnectionAgents) Stop(names ...string) {
	for _, n := range names {
		c.Get(n).Stop()
		c.Get(n).Join()
	}
}

func (c *ConnectionAgents) StopAll() {
	for _, a := range c.agents {
		a.Stop()
		a.Join()
	}
}

// This function sends an (CONNECTION|APPLICATION)_CLOSE frame and wait for it to be sent out. Then it stops all the
// agents attached to this connection.
func (c *ConnectionAgents) CloseConnection(quicLayer bool, errorCode uint64, reasonPhrase string) {
	var a Agent
	var present bool
	if a, present = c.Has("ClosingAgent"); !present {
		a = &ClosingAgent{}
		c.Add(a)
	}
	a.(*ClosingAgent).Close(quicLayer, errorCode, reasonPhrase)
	a.Join()
	c.StopAll()
}

func (c *ConnectionAgents) AddHTTPAgent() HTTPAgent {
	var agent HTTPAgent
	if strings.HasPrefix(c.conn.ALPN, "h3") {
		agent = &HTTP3Agent{DisableQPACKStreams: true}
	} else {
		agent = &HTTP09Agent{}
	}
	c.Add(agent)
	return agent
}

// Returns the agents needed for a basic QUIC connection to operate
func GetDefaultAgents() []Agent {
	fc := &FlowControlAgent{}
	return []Agent{
		&QLogAgent{},
		&SocketAgent{},
		&ParsingAgent{},
		&BufferAgent{},
		&TLSAgent{},
		&AckAgent{},
		&SendingAgent{MTU: 1200},
		&RecoveryAgent{TimerValue: 500 * time.Millisecond},
		&RTTAgent{},
		&FrameQueueAgent{},
		fc,
		&StreamAgent{FlowControlAgent: fc},
		&ClosingAgent{},
	}
}
