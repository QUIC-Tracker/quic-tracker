package qlog

type MetricUpdate struct {
	CongestionWindow uint64 `json:"congestion_window,omitempty"`
	BytesInFlight    uint64 `json:"bytes_in_flight,omitempty"`
	MinRTT           uint64 `json:"min_rtt,omitempty"`
	SmoothedRTT      uint64 `json:"smoothed_rtt,omitempty"`
	LatestRTT        uint64 `json:"latest_rtt,omitempty"`
	MaxAckDelay      uint64 `json:"max_ack_delay,omitempty"`
	RTTVariance      uint64 `json:"rtt_variance,omitempty"`
	SSThresh         uint64 `json:"ssthresh,omitempty"`
	PacingRate       uint64 `json:"pacing_rate,omitempty"`
}
