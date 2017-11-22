package scenarii

import (
	m "masterthesis"
)

type Scenario interface {
	Name() string
	Version() int
	Run(conn *m.Connection, trace *m.Trace)
}

type AbstractScenario struct {
	name string
	version int
}
func (s *AbstractScenario) Name() string {
	return s.name
}
func (s *AbstractScenario) Version() int {
	return s.version
}