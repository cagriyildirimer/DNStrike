package models

import "time"

type ProtocolCheck struct {
	Available bool    `json:"available"`
	LatencyMS float64 `json:"latency_ms"`
	Error     string  `json:"error,omitempty"`
}

type DiscoveryProfile struct {
	Target           string        `json:"target"`
	CheckedAt        time.Time     `json:"checked_at"`
	UDP              ProtocolCheck `json:"udp"`
	TCP              ProtocolCheck `json:"tcp"`
	RecursionEnabled bool          `json:"recursion_enabled"`
	Authoritative    bool          `json:"authoritative"`
	EDNSSupported    bool          `json:"edns_supported"`
	DNSSECSupported  bool          `json:"dnssec_supported"`
	ResponseSize     int           `json:"response_size"`
	TCPFallback      bool          `json:"tcp_fallback"`
	AverageLatencyMS float64       `json:"average_latency_ms"`
	Flags            DNSFlags      `json:"flags"`
}

type DNSFlags struct {
	RA bool `json:"ra"`
	RD bool `json:"rd"`
	AA bool `json:"aa"`
	TC bool `json:"tc"`
}
