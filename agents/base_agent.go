package agents

import (
	. "github.com/mpiraux/master-thesis"
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
}

func (a *BaseAgent) Name() string { return a.name }

func (a *BaseAgent) Init(name string, SCID ConnectionID) {
	a.name = name
	a.Logger = log.New(os.Stdout, fmt.Sprintf("[%s/%s] ", hex.EncodeToString(SCID), a.Name()), log.LstdFlags | log.Lshortfile)
	a.Logger.Println("Agent started")
	a.close = make(chan bool)
}

func (a *BaseAgent) Stop() {
	close(a.close)
}

func (a *BaseAgent) Join() {
	<-a.close
}

type ConnectionAgents struct {
	conn *Connection
	agents map[string]Agent
}

func AttachAgentsToConnection(conn *Connection, agents ...Agent) ConnectionAgents {
	c := ConnectionAgents{conn, make(map[string]Agent)}

	for _, a := range agents {
		c.Add(a)
	}

	return c
}

func (c *ConnectionAgents) Add(agent Agent) {
	agent.Run(c.conn)
	c.agents[agent.Name()] = agent
}

func (c *ConnectionAgents) Get(name string) Agent {
	return c.agents[name]
}

var DefaultAgents = []Agent{
	&SocketAgent{},
	&ParsingAgent{},
	&BufferAgent{},
	&TLSAgent{},
	&AckAgent{},
	&SendingAgent{MTU: 1200},
	&RecoveryAgent{TimerValue: 500 * time.Millisecond},
}