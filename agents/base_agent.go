package agents

import (
	. "github.com/QUIC-Tracker/quic-tracker"
	"log"
	"os"
	"fmt"
	"encoding/hex"
	"time"
)

type Agent interface {
	Name() string
	Init(name string, SCID ConnectionID)
	Run(conn *Connection)
	Stop()
	Join()
}

type BaseAgent struct {
	name   string
	Logger *log.Logger
	close  chan bool
	closed chan bool
}

func (a *BaseAgent) Name() string { return a.name }

func (a *BaseAgent) Init(name string, SCID ConnectionID) {
	a.name = name
	a.Logger = log.New(os.Stdout, fmt.Sprintf("[%s/%s] ", hex.EncodeToString(SCID), a.Name()), log.Lshortfile)
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

func (a *BaseAgent) Join() {
	<-a.closed
}

type ConnectionAgents struct {
	conn   *Connection
	agents map[string]Agent
}

func AttachAgentsToConnection(conn *Connection, agents ...Agent) *ConnectionAgents {
	c := ConnectionAgents{conn, make(map[string]Agent)}

	for _, a := range agents {
		c.Add(a)
	}

	return &c
}

func (c *ConnectionAgents) Add(agent Agent) {
	agent.Run(c.conn)
	c.agents[agent.Name()] = agent
}

func (c *ConnectionAgents) Get(name string) Agent {
	return c.agents[name]
}

func (c *ConnectionAgents) StopAll() {
	for _, a := range c.agents {
		a.Stop()
		a.Join()
	}
}

func (c *ConnectionAgents) CloseConnection(quicLayer bool, errorCode uint16, reasonPhrase string) {
	a := &ClosingAgent{QuicLayer: quicLayer, ErrorCode: errorCode, ReasonPhrase: reasonPhrase}
	c.Add(a)
	a.Join()
	c.StopAll()
}

func GetDefaultAgents() []Agent {
	return []Agent{
		&SocketAgent{},
		&ParsingAgent{},
		&BufferAgent{},
		&TLSAgent{},
		&AckAgent{},
		&SendingAgent{MTU: 1200},
		&RecoveryAgent{TimerValue: 500 * time.Millisecond},
	}
}
