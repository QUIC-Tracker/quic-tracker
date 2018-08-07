package agents

import (
	m "github.com/mpiraux/master-thesis"
	"log"
	"os"
	"fmt"
	"encoding/hex"
)

type Agent interface {
	Init(name string, SCID m.ConnectionID)
	Run(conn *m.Connection)
	Stop()
	Join()
}

type BaseAgent struct {
	Name   string
	Logger *log.Logger
	close  chan bool
}

func (a *BaseAgent) Init(name string, SCID m.ConnectionID) {
	a.Name = name
	a.Logger = log.New(os.Stdout, fmt.Sprintf("[%s/%s] ", hex.EncodeToString(SCID), a.Name), log.LstdFlags | log.Lshortfile)
	a.Logger.Println("Agent started")
	a.close = make(chan bool)
}

func (a *BaseAgent) Stop() {
	close(a.close)
}

func (a *BaseAgent) Join() {
	<-a.close
}