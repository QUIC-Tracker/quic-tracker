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
	GenericPacket
}

func NewConcreteSymbol(packet interface{}) ConcreteSymbol {
	cs := packet.(ConcreteSymbol)
	return cs
}

func (cs ConcreteSymbol) String() string {
	ba, err := json.Marshal(cs)
	if err != nil {
		fmt.Printf("Failed to Marshal ConcreteSymbol: %v", err.Error())
	}

	return string(ba)
}

type ConcreteSet struct {
	internalSet mapset.Set // type: ConcreteSymbol
}

func NewConcreteSet() *ConcreteSet {
	cs := ConcreteSet{internalSet: mapset.NewSet()}
	return &cs
}

func (as *ConcreteSet) Add(concreteSymbol ConcreteSymbol) {
	as.internalSet.Add(concreteSymbol)
}

func (as *ConcreteSet) Clear() {
	as.internalSet.Clear()
}

func (cs ConcreteSet) String() string {
	if cs.internalSet.Cardinality() == 0 {
		return "[]"
	}

	setSlice := cs.internalSet.ToSlice()
	stringSlice := []string{}
	for index, setElement := range setSlice {
		stringSlice[index] = setElement.(ConcreteSymbol).String()
	}
	sort.Strings(stringSlice)

	return fmt.Sprintf("[%v]", strings.Join(stringSlice, ","))
}

type ConcreteOrderedPair struct {
	concreteInputs []*ConcreteSymbol
	concreteOutputs []ConcreteSet
}

func (ct *ConcreteOrderedPair) Input() *[]*ConcreteSymbol {
	return &ct.concreteInputs
}

func (ct *ConcreteOrderedPair) Output() *[]ConcreteSet {
	return &ct.concreteOutputs
}

func (ct *ConcreteOrderedPair) SetInput(concreteSymbols []*ConcreteSymbol) {
	(*ct).concreteInputs = concreteSymbols
}

func (ct *ConcreteOrderedPair) SetOutput(concreteSets []ConcreteSet) {
	(*ct).concreteOutputs = concreteSets
}

func (ct ConcreteOrderedPair) String() string {
	ciStringSlice := []string{}
	for _, value := range ct.concreteInputs {
		if value != nil {
			ciStringSlice = append(ciStringSlice, value.String())
		} else {
			ciStringSlice = append(ciStringSlice, "NIL")
		}

	}
	ciString := fmt.Sprintf("[%v]", strings.Join(ciStringSlice, ","))

	coStringSlice := []string{}
	for _, value := range ct.concreteOutputs {
		coStringSlice = append(coStringSlice, value.String())
	}
	coString := fmt.Sprintf("[%v]", strings.Join(coStringSlice, ","))
	return fmt.Sprintf("(%v,%v)", ciString, coString)
}

