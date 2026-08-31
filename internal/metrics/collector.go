package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
	"github.com/miekg/dns"
)

const DefaultLatencySamples = 8192

type Collector struct {
	started          time.Time
	total            atomic.Uint64
	responses        atomic.Uint64
	timeouts         atomic.Uint64
	errors           atomic.Uint64
	rcodes           [16]atomic.Uint64
	otherRCodes      atomic.Uint64
	latencySumMicros atomic.Uint64
	latencyCount     atomic.Uint64
	latencyMinMicros atomic.Int64
	latencyMaxMicros atomic.Int64
	latencyIndex     atomic.Uint64
	latencies        []atomic.Int64
	snapshotMu       sync.Mutex
	lastSnapshot     time.Time
	lastTotal        uint64
	lastResponses    uint64
}

func NewCollector(sampleCapacity int) *Collector {
	if sampleCapacity < 1 {
		sampleCapacity = DefaultLatencySamples
	}
	now := time.Now().UTC()
	collector := &Collector{started: now, lastSnapshot: now, latencies: make([]atomic.Int64, sampleCapacity)}
	collector.latencyMinMicros.Store(-1)
	return collector
}

func (c *Collector) Record(result models.QueryResult) {
	c.total.Add(1)
	if result.ErrorClass == models.QueryTimeout {
		c.timeouts.Add(1)
	}
	if result.ErrorClass != "" {
		c.errors.Add(1)
	} else {
		c.responses.Add(1)
		if result.RCode >= 0 && result.RCode < len(c.rcodes) {
			c.rcodes[result.RCode].Add(1)
		} else {
			c.otherRCodes.Add(1)
		}
	}
	if result.Latency <= 0 {
		return
	}
	micros := result.Latency.Microseconds()
	if micros < 1 {
		micros = 1
	}
	c.latencySumMicros.Add(uint64(micros))
	c.latencyCount.Add(1)
	updateMin(&c.latencyMinMicros, micros)
	updateMax(&c.latencyMaxMicros, micros)
	index := c.latencyIndex.Add(1) - 1
	c.latencies[index%uint64(len(c.latencies))].Store(micros)
}

func (c *Collector) Snapshot(now time.Time) models.MetricSnapshot {
	now = now.UTC()
	c.snapshotMu.Lock()
	defer c.snapshotMu.Unlock()
	total := c.total.Load()
	responses := c.responses.Load()
	interval := now.Sub(c.lastSnapshot).Seconds()
	if interval <= 0 {
		interval = 1
	}
	snapshot := models.MetricSnapshot{Timestamp: now, ElapsedSeconds: now.Sub(c.started).Seconds(), CurrentQPS: float64(total-c.lastTotal) / interval, ResponsesPerSec: float64(responses-c.lastResponses) / interval, TotalQueries: total, TotalResponses: responses, Timeouts: c.timeouts.Load(), Errors: c.errors.Load(), ResponseCodes: make(map[string]uint64)}
	c.lastSnapshot = now
	c.lastTotal = total
	c.lastResponses = responses
	if total > 0 {
		snapshot.TimeoutPercent = float64(snapshot.Timeouts) * 100 / float64(total)
	}
	for code := range c.rcodes {
		count := c.rcodes[code].Load()
		if count > 0 {
			name := dns.RcodeToString[code]
			if name == "" {
				name = "OTHER"
			}
			snapshot.ResponseCodes[name] = count
		}
	}
	if other := c.otherRCodes.Load(); other > 0 {
		snapshot.ResponseCodes["OTHER"] += other
	}
	count := c.latencyCount.Load()
	if count > 0 {
		snapshot.MinLatencyMS = float64(c.latencyMinMicros.Load()) / 1000
		snapshot.MaxLatencyMS = float64(c.latencyMaxMicros.Load()) / 1000
		snapshot.AverageLatencyMS = float64(c.latencySumMicros.Load()) / float64(count) / 1000
		samples := c.samples()
		snapshot.P50LatencyMS = percentile(samples, 50)
		snapshot.P90LatencyMS = percentile(samples, 90)
		snapshot.P95LatencyMS = percentile(samples, 95)
		snapshot.P99LatencyMS = percentile(samples, 99)
	}
	return snapshot
}

func (c *Collector) samples() []int64 {
	written := c.latencyIndex.Load()
	size := uint64(len(c.latencies))
	if written < size {
		size = written
	}
	samples := make([]int64, 0, size)
	for i := uint64(0); i < size; i++ {
		value := c.latencies[i].Load()
		if value > 0 {
			samples = append(samples, value)
		}
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	return samples
}
func percentile(sortedMicros []int64, p int) float64 {
	if len(sortedMicros) == 0 {
		return 0
	}
	rank := (p*len(sortedMicros) + 99) / 100
	if rank < 1 {
		rank = 1
	}
	if rank > len(sortedMicros) {
		rank = len(sortedMicros)
	}
	return float64(sortedMicros[rank-1]) / 1000
}
func updateMin(value *atomic.Int64, candidate int64) {
	for {
		current := value.Load()
		if current >= 0 && current <= candidate {
			return
		}
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
func updateMax(value *atomic.Int64, candidate int64) {
	for {
		current := value.Load()
		if current >= candidate {
			return
		}
		if value.CompareAndSwap(current, candidate) {
			return
		}
	}
}
