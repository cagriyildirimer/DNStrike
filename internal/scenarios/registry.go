package scenarios

import (
	"sort"
	"sync"

	"github.com/dnstrike/dnstrike/pkg/models"
)

type Scenario interface {
	Metadata() models.ScenarioMetadata
}
type Registry struct {
	mu    sync.RWMutex
	items map[string]Scenario
}

func NewRegistry() *Registry { return &Registry{items: make(map[string]Scenario)} }
func (r *Registry) Register(s Scenario) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.items[s.Metadata().ID] = s
}
func (r *Registry) List() []models.ScenarioMetadata {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]models.ScenarioMetadata, 0, len(r.items))
	for _, s := range r.items {
		out = append(out, s.Metadata())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (r *Registry) Get(id string) (models.ScenarioMetadata, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.items[id]
	if !ok {
		return models.ScenarioMetadata{}, false
	}
	return s.Metadata(), true
}

type metadataScenario struct{ metadata models.ScenarioMetadata }

func (s metadataScenario) Metadata() models.ScenarioMetadata { return s.metadata }

func DefaultRegistry() *Registry {
	r := NewRegistry()
	limit := models.Limits{MaxQPS: 10000, MaxDuration: 300, MaxWorkers: 256}
	definitions := []models.ScenarioMetadata{
		{ID: "security-audit", Name: "Security Audit", Category: "audit", Description: "Recursion, response flags, EDNS and DNSSEC posture checks.", SupportedProtocols: []string{"udp", "tcp"}, RiskLevel: "LOW", DefaultConfig: map[string]any{"domain": "example.com"}, RecommendedLimits: models.Limits{MaxQPS: 10, MaxDuration: 30, MaxWorkers: 2}},
		{ID: "zone-transfer-audit", Name: "AXFR Zone Transfer Leak Audit", Category: "audit", Description: "Attempts unauthorized AXFR/IXFR zone transfers over TCP 53 to audit domain database leakage.", SupportedProtocols: []string{"tcp"}, RiskLevel: "LOW", DefaultConfig: map[string]any{"domain": "example.com"}, RecommendedLimits: models.Limits{MaxQPS: 10, MaxDuration: 30, MaxWorkers: 2}},
		{ID: "amplification-audit", Name: "DNS Amplification & RRL Audit", Category: "audit", Description: "Measures DNS response amplification factors (ANY, TXT, DNSKEY, EDNS0) and checks Response Rate Limiting (RRL) posture.", SupportedProtocols: []string{"udp", "tcp"}, RiskLevel: "MEDIUM", DefaultConfig: map[string]any{"domain": "example.com"}, RecommendedLimits: models.Limits{MaxQPS: 50, MaxDuration: 30, MaxWorkers: 5}},
		{ID: "dns-fuzzing", Name: "DNS Fuzzing & Malformed Packet Test", Category: "audit", Description: "Sends malformed DNS UDP frames (header bit-flips, label overflow, invalid EDNS0) to evaluate crash resilience.", SupportedProtocols: []string{"udp"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"domain": "example.com"}, RecommendedLimits: models.Limits{MaxQPS: 20, MaxDuration: 30, MaxWorkers: 2}},
		{ID: "subdomain-takeover", Name: "Subdomain Takeover / Dangling CNAME Scanner", Category: "audit", Description: "Scans CNAME records for dangling external cloud provider pointers (AWS S3, GitHub Pages, Heroku, Azure, Vercel, Netlify) vulnerable to takeover.", SupportedProtocols: []string{"udp", "tcp"}, RiskLevel: "LOW", DefaultConfig: map[string]any{"domain": "example.com", "subdomains": []string{"api", "dev", "stage", "blog", "shop", "app", "docs", "status", "mail", "cdn"}}, RecommendedLimits: models.Limits{MaxQPS: 20, MaxDuration: 60, MaxWorkers: 5}},
		{ID: "rrl-threshold", Name: "Response Rate Limiting & SLIP Threshold Test", Category: "audit", Description: "Ramps UDP query bursts to identify exact RRL rate-limit thresholds, dropped packet rates, and TC=1 SLIP fallback behaviors.", SupportedProtocols: []string{"udp"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"domain": "example.com", "max_burst_qps": 500}, RecommendedLimits: models.Limits{MaxQPS: 500, MaxDuration: 60, MaxWorkers: 10}},
		{ID: "benchmark", Name: "Performance Benchmark", Category: "performance", Description: "Rate-limited DNS response and latency benchmark.", SupportedProtocols: []string{"udp", "tcp"}, RequiredParameters: []string{"qps", "duration", "workers"}, RiskLevel: "MEDIUM", DefaultConfig: map[string]any{"qps": 100, "duration": 10, "workers": 10, "source_ip_pool": ""}, RecommendedLimits: limit},
		{ID: "qps-ramp", Name: "QPS Ramp", Category: "performance", Description: "Find the maximum stable query rate in bounded steps.", SupportedProtocols: []string{"udp", "tcp"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"start_qps": 100, "step_qps": 100, "max_qps": 1000, "step_duration": 10, "source_ip_pool": ""}, RecommendedLimits: limit},
		{ID: "nxdomain", Name: "NXDOMAIN Resilience", Category: "resolver-cache", Description: "Unique controlled-name workload for negative-cache resilience.", SupportedProtocols: []string{"udp", "tcp"}, RequiredParameters: []string{"base_domain", "qps", "duration"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"base_domain": "invalid-test.local", "qps": 100, "duration": 10, "workers": 10, "source_ip_pool": ""}, RecommendedLimits: limit},
		{ID: "random-subdomain", Name: "Random Subdomain", Category: "resolver-cache", Description: "Unique subdomain workload against a user-controlled namespace.", SupportedProtocols: []string{"udp", "tcp"}, RequiredParameters: []string{"base_domain", "qps", "duration"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"qps": 100, "duration": 10, "workers": 10, "source_ip_pool": ""}, RecommendedLimits: limit},
		{ID: "query-flood", Name: "Query Flood", Category: "volume", Description: "Bounded single-record-type DNS workload.", SupportedProtocols: []string{"udp", "tcp"}, RequiredParameters: []string{"domain_list", "query_type", "qps", "duration"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"query_type": "A", "qps": 100, "duration": 10, "workers": 10, "domain_list": []string{}, "source_ip_pool": ""}, RecommendedLimits: limit},
		{ID: "tcp-slowloris", Name: "DNS TCP Slowloris / Connection Exhaustion", Category: "volume", Description: "Simulates TCP connection exhaustion on port 53 by holding slow concurrent TCP sockets open.", SupportedProtocols: []string{"tcp"}, RiskLevel: "HIGH", DefaultConfig: map[string]any{"connections": 20, "hold_duration": 10}, RecommendedLimits: models.Limits{MaxQPS: 100, MaxDuration: 120, MaxWorkers: 50}},
	}
	for _, d := range definitions {
		r.Register(metadataScenario{d})
	}
	return r
}
