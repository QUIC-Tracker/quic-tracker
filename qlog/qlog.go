package qlog

import (
	"encoding/json"
	"sort"
	"time"
)

const (
	TimeUnits       = time.Microsecond
	TimeUnitsString = "us"
)

type StreamType string

const (
	StreamTypeBidi StreamType = "bidirectional"
	StreamTypeUni  StreamType = "unidirectional"
)

var Categories = struct {
	Connectivity struct {
		Category               string
		ServerListening        string
		ConnectionStarted      string
		ConnectionIDUpdated    string
		SpinBitUpdated         string
		ConnectionRetried      string
		ConnectionStateUpdated string
	}
	Transport struct {
		Category           string
		PacketSent         string
		PacketReceived     string
		PacketDropped      string
		PacketBuffered     string
		StreamStateUpdated string
	}
	Recovery struct {
		Category               string
		MetricsUpdated         string
		CongestionStateUpdated string
		LossTimerSet           string
		LossTimerFired         string
		PacketLost             string
		MarkedForRetransmit    string
	}
}{
	struct {
		Category               string
		ServerListening        string
		ConnectionStarted      string
		ConnectionIDUpdated    string
		SpinBitUpdated         string
		ConnectionRetried      string
		ConnectionStateUpdated string
	}{"connectivity", "server_listening", "connection_started", "connection_id_updated", "spin_bit_updated", "connection_retried", "connection_state_updated"},
	struct {
		Category           string
		PacketSent         string
		PacketReceived     string
		PacketDropped      string
		PacketBuffered     string
		StreamStateUpdated string
	}{"transport", "packet_sent", "packet_received", "packet_dropped", "packet_buffered", "stream_state_updated"},
	struct {
		Category               string
		MetricsUpdated         string
		CongestionStateUpdated string
		LossTimerSet           string
		LossTimerFired         string
		PacketLost             string
		MarkedForRetransmit    string
	}{"recovery", "metrics_updated", "congestion_state_updated", "loss_timer_set", "loss_timer_fired", "packet_lost", "marked_for_retransmit"},
}

type Event struct {
	RelativeTime uint64
	Category     string
	Event        string
	Data         interface{}
}

func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{e.RelativeTime, e.Category, e.Event, e.Data})
}

func DefaultEventFields() []string {
	return []string{"relative_time", "category", "event", "data"}
}

type Trace struct {
	VantagePoint struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"vantage_point"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Configuration struct {
		TimeOffset uint64 `json:"time_offset,string"`
		TimeUnits  string `json:"time_units"`
	} `json:"configuration"`
	CommonFields map[string]interface{} `json:"common_fields"`
	EventFields  []string               `json:"event_fields"`
	Events       []*Event               `json:"events"`

	ReferenceTime time.Time `json:"-"`
}

func (t *Trace) NewEvent(category, eventType string, data interface{}) *Event {
	e := new(Event)
	e.RelativeTime = uint64(time.Now().Sub(t.ReferenceTime) / TimeUnits)
	e.Category = category
	e.Event = eventType
	e.Data = data
	return e
}

func (t *Trace) Add(e *Event) {
	t.Events = append(t.Events, e)
}

func (t *Trace) Sort() {
	sort.Slice(t.Events, func(i, j int) bool {
		return t.Events[i].RelativeTime < t.Events[j].RelativeTime
	})
}

type QLog struct {
	Version     string                 `json:"qlog_version"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Summary     map[string]interface{} `json:"summary"`
	Traces      []*Trace               `json:"traces"`
}
