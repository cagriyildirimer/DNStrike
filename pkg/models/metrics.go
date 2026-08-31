package models

import "time"

type MetricSnapshot struct {
	Timestamp        time.Time         `json:"timestamp"`
	ElapsedSeconds   float64           `json:"elapsed_seconds"`
	CurrentQPS       float64           `json:"current_qps"`
	ResponsesPerSec  float64           `json:"responses_per_second"`
	TotalQueries     uint64            `json:"total_queries"`
	TotalResponses   uint64            `json:"total_responses"`
	Timeouts         uint64            `json:"timeouts"`
	TimeoutPercent   float64           `json:"timeout_percent"`
	Errors           uint64            `json:"errors"`
	ResponseCodes    map[string]uint64 `json:"response_codes"`
	MinLatencyMS     float64           `json:"min_latency_ms"`
	AverageLatencyMS float64           `json:"average_latency_ms"`
	MaxLatencyMS     float64           `json:"max_latency_ms"`
	P50LatencyMS     float64           `json:"p50_latency_ms"`
	P90LatencyMS     float64           `json:"p90_latency_ms"`
	P95LatencyMS     float64           `json:"p95_latency_ms"`
	P99LatencyMS     float64           `json:"p99_latency_ms"`
}
