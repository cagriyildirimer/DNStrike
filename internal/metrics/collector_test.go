package metrics

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
	"github.com/miekg/dns"
)

func TestCollectorCalculatesMetricsAndPercentiles(t *testing.T) {
	collector := NewCollector(200)
	for i := 1; i <= 100; i++ {
		collector.Record(models.QueryResult{Latency: time.Duration(i) * time.Millisecond, RCode: dns.RcodeSuccess})
	}
	collector.Record(models.QueryResult{ErrorClass: models.QueryTimeout})
	collector.Record(models.QueryResult{Latency: 5 * time.Millisecond, RCode: dns.RcodeNameError})
	snapshot := collector.Snapshot(time.Now().Add(time.Second))
	if snapshot.TotalQueries != 102 || snapshot.TotalResponses != 101 || snapshot.Timeouts != 1 {
		t.Fatalf("unexpected counters: %#v", snapshot)
	}
	if snapshot.ResponseCodes["NOERROR"] != 100 || snapshot.ResponseCodes["NXDOMAIN"] != 1 {
		t.Fatalf("unexpected rcodes: %#v", snapshot.ResponseCodes)
	}
	if snapshot.P50LatencyMS != 50 || snapshot.P95LatencyMS != 95 || snapshot.P99LatencyMS != 99 {
		t.Fatalf("unexpected percentiles: p50=%v p95=%v p99=%v", snapshot.P50LatencyMS, snapshot.P95LatencyMS, snapshot.P99LatencyMS)
	}
}

func TestCollectorUsesBoundedLatencyRing(t *testing.T) {
	collector := NewCollector(4)
	for i := 1; i <= 10; i++ {
		collector.Record(models.QueryResult{Latency: time.Duration(i) * time.Millisecond, RCode: dns.RcodeSuccess})
	}
	samples := collector.samples()
	if len(samples) != 4 {
		t.Fatalf("expected four samples, got %d", len(samples))
	}
	if fmt.Sprint(samples) != "[7000 8000 9000 10000]" {
		t.Fatalf("ring does not contain latest values: %v", samples)
	}
}

func TestCollectorConcurrentRecording(t *testing.T) {
	collector := NewCollector(128)
	var workers sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 1000; i++ {
				collector.Record(models.QueryResult{Latency: time.Millisecond, RCode: dns.RcodeSuccess})
			}
		}()
	}
	workers.Wait()
	snapshot := collector.Snapshot(time.Now().Add(time.Second))
	if snapshot.TotalQueries != 8000 || snapshot.TotalResponses != 8000 {
		t.Fatalf("lost concurrent metrics: %#v", snapshot)
	}
}
