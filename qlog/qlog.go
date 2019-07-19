package qlog

import (
	"encoding/json"
	"time"
)

const (
	TimeUnits       = time.Millisecond
	TimeUnitsString = "ms"
)

var Categories = struct {
	Transport struct {
		Category                  string
		PacketSent                string
		PacketReceived            string
		PacketDropped             string
		VersionUpdate             string
		TransportParametersUpdate string
		ALPNUpdate                string
		StreamStateUpdate         string
		FlowControlUpdate         string
	}
	Recovery struct {
		Category           string
		CCStateUpdate      string
		MetricUpdate       string
		LossAlarmSet       string
		LossAlarmFired     string
		PacketLost         string
		PacketAcknowledged string
		PacketRetransmit   string
	}
}{
	struct {
		Category                  string
		PacketSent                string
		PacketReceived            string
		PacketDropped             string
		VersionUpdate             string
		TransportParametersUpdate string
		ALPNUpdate                string
		StreamStateUpdate         string
		FlowControlUpdate         string
	}{"TRANSPORT", "PACKET_SENT", "PACKET_RECEIVED", "PACKET_DROPPED", "VERSION_UPDATE", "TRANSPORT_PARAMETERS_UPDATE", "ALPN_UPDATE", "STREAM_STATE_UPDATE", "FLOW_CONTROL_UPDATE"},
	struct {
		Category           string
		CCStateUpdate      string
		MetricUpdate       string
		LossAlarmSet       string
		LossAlarmFired     string
		PacketLost         string
		PacketAcknowledged string
		PacketRetransmit   string
	}{"RECOVERY", "CC_STATE_UPDATE", "METRIC_UPDATE", "LOSS_ALARM_SET", "LOSS_ALARM_FIRED", "PACKET_LOST", "PACKET_ACKNOWLEDGED", "PACKET_RETRANSMIT"},
}

type Event struct {
	RelativeTime uint64
	Category     string
	EventType    string
	Trigger      string
	Data         interface{}
}

func (e *Event) MarshalJSON() ([]byte, error) {
	return json.Marshal([]interface{}{e.RelativeTime, e.Category, e.EventType, e.Trigger, e.Data})
}

func DefaultEventFields() []string {
	return []string{"relative_time", "CATEGORY", "EVENT_TYPE", "TRIGGER", "DATA"}
}

type Trace struct {
	VantagePoint struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"vantage_point"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Configuration struct {
		TimeOffset uint64 `json:"time_offset"`
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
	if len(e.Trigger) == 0 {
		e.Trigger = "DEFAULT"
	}
	e.Category = category
	e.EventType = eventType
	e.Data = data
	return e
}

func (t *Trace) Add(e *Event) {
	t.Events = append(t.Events, e)
}

type QLog struct {
	Version     string                 `json:"qlog_version"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Summary     map[string]interface{} `json:"summary"`
	Traces      []*Trace               `json:"traces"`
}
