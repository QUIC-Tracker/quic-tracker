package adapter

import (
	"encoding/json"
	"fmt"
	mapset "github.com/deckarep/golang-set"
	"sort"
	"strings"
)

type GenericPacket interface{}
type ConcreteSymbol struct {
	GenericPacket `json:"Packet"`
}

func NewConcreteSymbol(packet interface{}) ConcreteSymbol {
	gp := packet.(GenericPacket)
	cs := ConcreteSymbol{gp}
	return cs
}

func (cs *ConcreteSymbol) String() string {
	ba, err := json.Marshal(cs)
	if err != nil {
		fmt.Printf("Failed to Marshal ConcreteSymbol: %v", err.Error())
	}

	return string(ba)
}

type ConcreteSet struct {
	SymbolSet mapset.Set // type: ConcreteSymbol
}

func NewConcreteSet() *ConcreteSet {
	cs := ConcreteSet{SymbolSet: mapset.NewSet()}
	return &cs
}

func (as *ConcreteSet) Add(concreteSymbol ConcreteSymbol) {
	as.SymbolSet.Add(concreteSymbol)
}

func (as *ConcreteSet) Clear() {
	as.SymbolSet.Clear()
}

func (cs *ConcreteSet) String() string {
	if cs.SymbolSet.Cardinality() == 0 {
		return "{}"
	}

	setSlice := cs.SymbolSet.ToSlice()
	stringSlice := []string{}
	for _, setElement := range setSlice {
		symbol := setElement.(ConcreteSymbol)
		stringSlice = append(stringSlice, (&symbol).String())
	}
	sort.Strings(stringSlice)

	return fmt.Sprintf("{%v}", strings.Join(stringSlice, ","))
}

type ConcreteOrderedPair struct {
	ConcreteInputs  []*ConcreteSymbol
	ConcreteOutputs []ConcreteSet
}

func (ct *ConcreteOrderedPair) Input() *[]*ConcreteSymbol {
	return &ct.ConcreteInputs
}

func (ct *ConcreteOrderedPair) Output() *[]ConcreteSet {
	return &ct.ConcreteOutputs
}

func (ct *ConcreteOrderedPair) SetInput(concreteSymbols []*ConcreteSymbol) {
	(*ct).ConcreteInputs = concreteSymbols
}

func (ct *ConcreteOrderedPair) SetOutput(concreteSets []ConcreteSet) {
	(*ct).ConcreteOutputs = concreteSets
}

func (ct *ConcreteOrderedPair) String() string {
	ciStringSlice := []string{}
	for _, value := range ct.ConcreteInputs {
		if value != nil {
			ciStringSlice = append(ciStringSlice, value.String())
		} else {
			ciStringSlice = append(ciStringSlice, "NIL")
		}

	}
	ciString := fmt.Sprintf("[%v]", strings.Join(ciStringSlice, ","))

	coStringSlice := []string{}
	for _, value := range ct.ConcreteOutputs {
		coStringSlice = append(coStringSlice, value.String())
	}
	coString := fmt.Sprintf("[%v]", strings.Join(coStringSlice, ","))
	return fmt.Sprintf("(%v,%v)", ciString, coString)
}
