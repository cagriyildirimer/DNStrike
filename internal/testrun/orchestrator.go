package testrun

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/dnstrike/dnstrike/internal/dnsengine"
	"github.com/dnstrike/dnstrike/internal/metrics"
	"github.com/dnstrike/dnstrike/internal/scenarios"
	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type axfrRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
}

func performAXFR(target models.Target, domain string, timeout time.Duration) ([]axfrRecord, map[string]int, int, bool, string) {
	recordCounts := make(map[string]int)
	if !target.TCPEnabled {
		return nil, recordCounts, 0, true, "TCP is disabled on target"
	}
	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))
	transfer := new(dns.Transfer)
	transfer.ReadTimeout = timeout

	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ch, err := transfer.In(m, address)
	if err != nil {
		return nil, recordCounts, 0, true, err.Error()
	}

	var records []axfrRecord
	totalLeaked := 0

	for env := range ch {
		if env.Error != nil {
			return records, recordCounts, totalLeaked, true, env.Error.Error()
		}
		for _, rr := range env.RR {
			totalLeaked++
			header := rr.Header()
			recType := dns.TypeToString[header.Rrtype]
			recordCounts[recType]++

			if len(records) < 50 {
				records = append(records, axfrRecord{
					Name:  header.Name,
					Type:  recType,
					Value: strings.TrimSpace(strings.TrimPrefix(rr.String(), header.String())),
				})
			}
		}
	}
	return records, recordCounts, totalLeaked, false, ""
}

type Orchestrator struct {
	tests     *Service
	targets   TargetRepository
	scenarios *scenarios.Registry
	hub       *ws.Hub
	quit      chan struct{}
	wg        sync.WaitGroup
}

func NewOrchestrator(tests *Service, targets TargetRepository, scenarios *scenarios.Registry, hub *ws.Hub) *Orchestrator {
	return &Orchestrator{
		tests:     tests,
		targets:   targets,
		scenarios: scenarios,
		hub:       hub,
		quit:      make(chan struct{}),
	}
}

func (o *Orchestrator) Start() {
	o.wg.Add(1)
	go o.loop()
}

func (o *Orchestrator) Stop() {
	close(o.quit)
	o.wg.Wait()
}

func (o *Orchestrator) loop() {
	defer o.wg.Done()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-o.quit:
			return
		case <-ticker.C:
			o.pollPending()
		}
	}
}

func (o *Orchestrator) pollPending() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pendingTests, err := o.tests.List(ctx, models.TestFilter{Status: models.TestPending, Limit: 10})
	if err != nil {
		slog.Error("orchestrator failed to list pending tests", "error", err)
		return
	}

	for _, test := range pendingTests {
		go o.executeTest(test.ID)
	}
}

func (o *Orchestrator) executeTest(id int64) {
	ctx := context.Background() // Test runs independently of poller timeout

	// Mark as running
	test, err := o.tests.Transition(ctx, id, models.TestRunning, time.Now().UTC())
	if err != nil {
		slog.Error("orchestrator failed to transition to running", "test_id", id, "error", err)
		return
	}
	
	o.hub.Broadcast(fmt.Sprintf("%d", id), []byte(`{"type":"status_change","status":"RUNNING"}`))

	target, err := o.targets.GetTarget(ctx, test.TargetID)
	if err != nil {
		o.failTest(id, "target fetch failed")
		return
	}

	meta, ok := o.scenarios.Get(test.Scenario)
	if !ok {
		o.failTest(id, "unknown scenario")
		return
	}

	var config map[string]any
	if err := json.Unmarshal(test.Config, &config); err != nil {
		o.failTest(id, "invalid config")
		return
	}

	// Route to specific implementation based on category
	var execErr error
	var score int
	var result map[string]any

	// Parse and allocate Source IPs
	var sourceIPs []string
	if poolStr, ok := config["source_ip_pool"].(string); ok && poolStr != "" {
		for _, ipStr := range strings.Split(poolStr, ",") {
			ipStr = strings.TrimSpace(ipStr)
			if ipStr != "" {
				sourceIPs = append(sourceIPs, ipStr)
			}
		}
	}

	ipManager := dnsengine.NewIPManager()
	if len(sourceIPs) > 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", id), []byte(fmt.Sprintf(`{"type":"log","message":"Allocating %d Source IPs..."}`, len(sourceIPs))))
		var allocated []string
		for _, ip := range sourceIPs {
			if err := ipManager.Allocate(ip); err != nil {
				slog.Error("failed to allocate IP", "ip", ip, "error", err)
				o.hub.Broadcast(fmt.Sprintf("%d", id), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] Failed to allocate IP %s"}`, ip)))
			} else {
				allocated = append(allocated, ip)
			}
		}
		defer ipManager.ReleaseAll()
		config["_parsed_source_ips"] = allocated
	}

	slog.Info("orchestrator starting scenario", "test_id", id, "scenario", test.Scenario)
	
	switch meta.Category {
	case "audit":
		if meta.ID == "amplification-audit" {
			score, result, execErr = o.runAmplificationAuditScenario(ctx, test, target, meta, config)
		} else if meta.ID == "zone-transfer-audit" {
			score, result, execErr = o.runZoneTransferAuditScenario(ctx, test, target, meta, config)
		} else if meta.ID == "dns-fuzzing" {
			score, result, execErr = o.runDNSFuzzingScenario(ctx, test, target, meta, config)
		} else if meta.ID == "subdomain-takeover" {
			score, result, execErr = o.runSubdomainTakeoverScenario(ctx, test, target, meta, config)
		} else if meta.ID == "rrl-threshold" {
			score, result, execErr = o.runRRLThresholdScenario(ctx, test, target, meta, config)
		} else {
			score, result, execErr = o.runAuditScenario(ctx, test, target, meta, config)
		}
	case "performance", "volume":
		if meta.ID == "tcp-slowloris" {
			score, result, execErr = o.runTCPSlowlorisScenario(ctx, test, target, meta, config)
		} else {
			score, result, execErr = o.runPerformanceScenario(ctx, test, target, meta, config)
		}
	case "resolver-cache":
		score, result, execErr = o.runCacheScenario(ctx, test, target, meta, config)
	default:
		execErr = fmt.Errorf("unsupported category: %s", meta.Category)
	}

	if execErr != nil {
		slog.Error("test execution failed", "test_id", id, "error", execErr)
		o.failTest(id, execErr.Error())
		return
	}

	if result != nil {
		resultJSON, _ := json.Marshal(result)
		o.tests.SaveResult(ctx, id, score, resultJSON)
	} else {
		o.tests.SaveResult(ctx, id, score, []byte("{}"))
	}

	// Mark as completed
	_, err = o.tests.Transition(ctx, id, models.TestCompleted, time.Now().UTC())
	if err != nil {
		slog.Error("orchestrator failed to mark completed", "test_id", id, "error", err)
	}
	
	resultMsg := fmt.Sprintf(`{"type":"completed","score":%d}`, score)
	o.hub.Broadcast(fmt.Sprintf("%d", id), []byte(resultMsg))
}

func (o *Orchestrator) failTest(id int64, reason string) {
	_, err := o.tests.Transition(context.Background(), id, models.TestFailed, time.Now().UTC())
	if err != nil {
		slog.Error("orchestrator failed to mark failed", "test_id", id, "error", err)
	}
	msg, _ := json.Marshal(map[string]string{"type": "failed", "reason": reason})
	o.hub.Broadcast(fmt.Sprintf("%d", id), msg)
}

// Security Audit Logic
func (o *Orchestrator) runAuditScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"Starting Security Audit..."}`))
	
	score := 100
	engine := dnsengine.NewQueryEngine(3 * time.Second)
	
	// 1. Open Recursion Check
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[1/3] Checking for Open Recursion vulnerability..."}`))
	res, err := engine.Execute(ctx, target, models.DNSQuery{Domain: "google.com.", QueryType: "A", Protocol: "udp"})
	if err == nil && res.RCode == 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Target is an Open Resolver (Recursion enabled for external domains). Vulnerable to DNS Amplification attacks."}`))
		score -= 40
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target refused recursion for external domains."}`))
	}

	// 2. Information Leakage (version.bind)
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/3] Checking version.bind CHAOS TXT leakage..."}`))
	res, err = engine.Execute(ctx, target, models.DNSQuery{Domain: "version.bind.", QueryType: "TXT", Protocol: "udp"})
	if err == nil && res.RCode == 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Target leaked software version via CHAOS class query."}`))
		score -= 20
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target did not leak version.bind."}`))
	}

	// 3. AXFR (Zone Transfer)
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}
	
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[3/3] Attempting AXFR zone transfer for domain: %s"}`, domain)))
	
	_, _, leaked, failed, errStr := performAXFR(target, domain, 5*time.Second)
	if !failed && leaked > 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] AXFR Successful! Leaked %d zone records."}`, leaked)))
		score -= 40
	} else if failed {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] AXFR connection refused or timed out (%s)."}`, errStr)))
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR attempted but no records were returned."}`))
	}

	if score < 0 {
		score = 0
	}
	return score, nil, nil
}

// Amplification & RRL Audit Logic
func (o *Orchestrator) runAmplificationAuditScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"Starting DNS Amplification & RRL Audit..."}`))

	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	type queryConfig struct {
		qType string
		edns  bool
	}

	testsToRun := []queryConfig{
		{qType: "A", edns: false},
		{qType: "A", edns: true},
		{qType: "TXT", edns: true},
		{qType: "ANY", edns: true},
		{qType: "DNSKEY", edns: true},
	}

	type ampItem struct {
		QueryType     string  `json:"query_type"`
		EDNS0         bool    `json:"edns0"`
		RequestBytes  int     `json:"request_bytes"`
		ResponseBytes int     `json:"response_bytes"`
		Amplification float64 `json:"amplification"`
		RCode         string  `json:"rcode"`
		Status        string  `json:"status"`
	}

	var results []ampItem
	maxAmp := 0.0
	maxRespBytes := 0
	score := 100

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[1/2] Measuring query/response payload sizes and amplification factors..."}`))

	client := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	for _, tc := range testsToRun {
		m := new(dns.Msg)
		qTypeNum := dns.TypeA
		switch tc.qType {
		case "TXT":
			qTypeNum = dns.TypeTXT
		case "ANY":
			qTypeNum = dns.TypeANY
		case "DNSKEY":
			qTypeNum = dns.TypeDNSKEY
		}
		m.SetQuestion(dns.Fqdn(domain), qTypeNum)
		m.RecursionDesired = true
		if tc.edns {
			m.SetEdns0(4096, true)
		}

		reqLen := m.Len()
		resp, _, err := client.ExchangeContext(ctx, m, address)

		respLen := 0
		rcodeStr := "ERROR"
		amp := 0.0
		status := "SAFE"

		if err == nil && resp != nil {
			respLen = resp.Len()
			rcodeStr = dns.RcodeToString[resp.Rcode]
			if reqLen > 0 {
				amp = float64(respLen) / float64(reqLen)
			}
			if amp > 20.0 {
				status = "CRITICAL"
			} else if amp > 10.0 {
				status = "HIGH"
			} else if amp > 5.0 {
				status = "MODERATE"
			}
		} else if err != nil {
			rcodeStr = "TIMEOUT/REFUSED"
		}

		if amp > maxAmp {
			maxAmp = amp
		}
		if respLen > maxRespBytes {
			maxRespBytes = respLen
		}

		results = append(results, ampItem{
			QueryType:     tc.qType,
			EDNS0:         tc.edns,
			RequestBytes:  reqLen,
			ResponseBytes: respLen,
			Amplification: float64(int(amp*100)) / 100,
			RCode:         rcodeStr,
			Status:        status,
		})

		ednsLabel := "Standard"
		if tc.edns {
			ednsLabel = "EDNS0 4096"
		}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"- [%s (%s)] Req: %dB, Resp: %dB, Amplification: %.2fx, RCode: %s"}`, tc.qType, ednsLabel, reqLen, respLen, amp, rcodeStr)))
	}

	// 2. Response Rate Limiting (RRL) Burst Test
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/2] Running 50-query burst test for Response Rate Limiting (RRL)..."}`))

	burstMsg := new(dns.Msg)
	burstMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	burstMsg.RecursionDesired = true

	fastClient := &dns.Client{Net: "udp", Timeout: 800 * time.Millisecond}
	dropped := 0
	truncated := 0

	for i := 0; i < 50; i++ {
		resp, _, err := fastClient.ExchangeContext(ctx, burstMsg, address)
		if err != nil {
			dropped++
		} else if resp != nil && resp.Truncated {
			truncated++
		}
	}

	rrlActive := false
	rrlStatus := "NO RRL DETECTED"

	if dropped > 8 || truncated > 0 {
		rrlActive = true
		rrlStatus = "RRL ACTIVE"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] Response Rate Limiting is ACTIVE (Dropped: %d/50, Truncated: %d/50). Target restricts amplification relays."}`, dropped, truncated)))
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] No Response Rate Limiting (RRL) detected! Target responded to 100%% of burst queries."}`))
	}

	if maxAmp > 20.0 {
		score -= 40
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] High Response Amplification Factor detected (%.2fx)."}`, maxAmp)))
	} else if maxAmp > 10.0 {
		score -= 20
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] Moderate Response Amplification Factor detected (%.2fx)."}`, maxAmp)))
	}

	if !rrlActive {
		score -= 25
	}

	if score < 0 {
		score = 0
	}

	result := map[string]any{
		"domain":                   domain,
		"max_amplification_factor": float64(int(maxAmp*100)) / 100,
		"max_response_bytes":       maxRespBytes,
		"rrl_active":               rrlActive,
		"rrl_dropped_count":        dropped,
		"rrl_status":               rrlStatus,
		"amplification_results":    results,
	}

	return score, result, nil
}

// Performance Benchmark Logic
func (o *Orchestrator) runPerformanceScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	if meta.ID == "qps-ramp" {
		return o.runQPSRampScenario(ctx, test, target, meta, config)
	}

	qps := 100
	if val, ok := config["qps"].(float64); ok {
		qps = int(val)
	}
	
	workers := 10
	if val, ok := config["workers"].(float64); ok {
		workers = int(val)
	}
	
	duration := 10
	if val, ok := config["duration"].(float64); ok {
		duration = int(val)
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting benchmark with %d QPS using %d workers for %d seconds..."}`, qps, workers, duration)))
	
	engine := dnsengine.NewQueryEngine(1 * time.Second)
	pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
		Workers: workers,
		QPS:     qps,
		Burst:   qps / 10,
	})
	
	if err != nil {
		return 0, nil, err
	}

	jobs := make(chan models.DNSQuery)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(duration)*time.Second)
	defer cancel()

	var sourceIPs []string
	if val, ok := config["_parsed_source_ips"].([]string); ok {
		sourceIPs = val
	}

	// Start feeding jobs
	go func() {
		defer close(jobs)
		ipIdx := 0
		for {
			select {
			case <-runCtx.Done():
				return
			default:
					var srcIP string
					if len(sourceIPs) > 0 {
						srcIP = sourceIPs[ipIdx%len(sourceIPs)]
						ipIdx++
					}

					if meta.ID == "query-flood" {
						qt := "A"
						if val, ok := config["query_type"].(string); ok {
							qt = val
						}
						
						domain := "example.com"
						
						if val, ok := config["domain_list"].([]any); ok && len(val) > 0 {
							idx := time.Now().UnixNano() % int64(len(val))
							if strVal, isStr := val[idx].(string); isStr {
								domain = strVal
							}
						}
						
						jobs <- models.DNSQuery{
							Domain: domain + ".",
							QueryType: qt,
							Protocol: "udp",
							SourceIP: srcIP,
						}
					} else {
						jobs <- models.DNSQuery{
							Domain: "example.com.",
							QueryType: "A",
							Protocol: "udp",
							SourceIP: srcIP,
						}
					}
			}
		}
	}()

	results := pool.Run(runCtx, target, jobs)
	
	collector := metrics.NewCollector(8192)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	doneLoop := false
	for !doneLoop {
		select {
		case <-runCtx.Done():
			doneLoop = true
		case res, ok := <-results:
			if !ok {
				doneLoop = true
				break
			}
			collector.Record(res)
		case <-ticker.C:
			snap := collector.Snapshot(time.Now())
			if snap.TotalQueries > 0 {
				data, _ := json.Marshal(map[string]any{
					"type":           "metric",
					"elapsed":        snap.ElapsedSeconds,
					"qps":            snap.CurrentQPS,
					"total_queries":  snap.TotalQueries,
					"errors":         snap.Errors,
					"loss":           snap.Timeouts,
					"avg_latency_ms": snap.AverageLatencyMS,
					"p50_latency_ms": snap.P50LatencyMS,
					"p99_latency_ms": snap.P99LatencyMS,
				})
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), data)
			}
		}
	}

	if results != nil {
		for res := range results {
			collector.Record(res)
		}
	}

	snap := collector.Snapshot(time.Now())
	score := 100
	if snap.TotalQueries > 0 {
		errorRate := float64(snap.Errors) / float64(snap.TotalQueries)
		score = 100 - int(errorRate*100)
		if score < 0 {
			score = 0
		}
	}

	result := map[string]any{
		"total_queries":  snap.TotalQueries,
		"errors":         snap.Errors,
		"loss":           snap.Timeouts,
		"success":        snap.TotalResponses,
		"avg_latency_ms": snap.AverageLatencyMS,
		"p50_latency_ms": snap.P50LatencyMS,
		"p90_latency_ms": snap.P90LatencyMS,
		"p95_latency_ms": snap.P95LatencyMS,
		"p99_latency_ms": snap.P99LatencyMS,
		"rcodes":         snap.ResponseCodes,
	}

	return score, result, nil
}

// QPS Ramp Scenario
func (o *Orchestrator) runQPSRampScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	startQps := 100
	if val, ok := config["start_qps"].(float64); ok {
		startQps = int(val)
	}
	stepQps := 100
	if val, ok := config["step_qps"].(float64); ok {
		stepQps = int(val)
	}
	maxQps := 1000
	if val, ok := config["max_qps"].(float64); ok {
		maxQps = int(val)
	}
	stepDuration := 5
	if val, ok := config["step_duration"].(float64); ok {
		stepDuration = int(val)
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[QPS RAMP] Starting ramp test. Start: %d, Step: %d, Max: %d, Step Duration: %ds"}`, startQps, stepQps, maxQps, stepDuration)))
	
	currentQps := startQps
	engine := dnsengine.NewQueryEngine(1 * time.Second)
	
	finalScore := 100
	for currentQps <= maxQps {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Testing at %d QPS..."}`, currentQps)))
		
		pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
			Workers: 50, // Fixed high number for ramp
			QPS:     currentQps,
			Burst:   currentQps / 10,
		})
		
		if err != nil {
			return 0, nil, err
		}

		jobs := make(chan models.DNSQuery)
		stepCtx, cancel := context.WithTimeout(ctx, time.Duration(stepDuration)*time.Second)

		var sourceIPs []string
		if val, ok := config["_parsed_source_ips"].([]string); ok {
			sourceIPs = val
		}

		go func() {
			defer close(jobs)
			ipIdx := 0
			for {
				select {
				case <-stepCtx.Done():
					return
				default:
					var srcIP string
					if len(sourceIPs) > 0 {
						srcIP = sourceIPs[ipIdx%len(sourceIPs)]
						ipIdx++
					}
					jobs <- models.DNSQuery{
						Domain: "example.com.",
						QueryType: "A",
						Protocol: "udp",
						SourceIP: srcIP,
					}
				}
			}
		}()

		results := pool.Run(stepCtx, target, jobs)
		
		stepCollector := metrics.NewCollector(4096)
		ticker := time.NewTicker(1 * time.Second)
		
	drainLoop:
		for {
			select {
			case <-stepCtx.Done():
				ticker.Stop()
				if results != nil {
					for res := range results {
						stepCollector.Record(res)
					}
				}
				break drainLoop
			case res, ok := <-results:
				if !ok {
					ticker.Stop()
					break drainLoop
				}
				stepCollector.Record(res)
			case <-ticker.C:
				snap := stepCollector.Snapshot(time.Now())
				if snap.TotalQueries > 0 {
					data, _ := json.Marshal(map[string]any{
						"type":           "metric",
						"step_qps":       currentQps,
						"qps":            snap.CurrentQPS,
						"total_queries":  snap.TotalQueries,
						"errors":         snap.Errors,
						"loss":           snap.Timeouts,
						"avg_latency_ms": snap.AverageLatencyMS,
					})
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), data)
				}
			}
		}
		cancel()

		stepSnap := stepCollector.Snapshot(time.Now())
		stepTotal := int(stepSnap.TotalQueries)
		stepErrors := int(stepSnap.Errors)
		
		// Evaluate step
		errorRate := 0.0
		if stepTotal > 0 {
			errorRate = float64(stepErrors) / float64(stepTotal)
		}
		
		if errorRate > 0.1 { // More than 10% errors
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] Server failed at %d QPS. Error rate: %.2f%%"}`, currentQps, errorRate*100)))
			finalScore = int((float64(currentQps) / float64(maxQps)) * 100)
			break
		}
		
		currentQps += stepQps
	}
	
	if currentQps > maxQps {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] Target successfully handled max load of %d QPS"}`, maxQps)))
	}

	result := map[string]any{
		"max_qps_reached": currentQps - stepQps,
	}

	return finalScore, result, nil
}


// Cache Resilience Logic (NXDOMAIN)
func (o *Orchestrator) runCacheScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	qps := 100
	if val, ok := config["qps"].(float64); ok {
		qps = int(val)
	}
	workers := 10
	if val, ok := config["workers"].(float64); ok {
		workers = int(val)
	}
	duration := 10
	if val, ok := config["duration"].(float64); ok {
		duration = int(val)
	}
	baseDomain := "invalid-test.local"
	if val, ok := config["base_domain"].(string); ok {
		baseDomain = val
	}

	scenarioName := "[WATER TORTURE]"
	if meta.ID == "random-subdomain" {
		scenarioName = "[RANDOM SUBDOMAIN]"
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"%s Stressing cache with queries against *.%s for %d seconds..."}`, scenarioName, baseDomain, duration)))
	
	engine := dnsengine.NewQueryEngine(1 * time.Second)
	pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
		Workers: workers,
		QPS:     qps,
		Burst:   qps / 10,
	})
	
	if err != nil {
		return 0, nil, err
	}

	jobs := make(chan models.DNSQuery)
	runCtx, cancel := context.WithTimeout(ctx, time.Duration(duration)*time.Second)
	defer cancel()

	var sourceIPs []string
	if val, ok := config["_parsed_source_ips"].([]string); ok {
		sourceIPs = val
	}

	go func() {
		defer close(jobs)
		ipIdx := 0
		for {
			select {
			case <-runCtx.Done():
				return
			default:
				var srcIP string
				if len(sourceIPs) > 0 {
					srcIP = sourceIPs[ipIdx%len(sourceIPs)]
					ipIdx++
				}
				jobs <- models.DNSQuery{
					Domain: fmt.Sprintf("%d.%s.", time.Now().UnixNano(), baseDomain),
					QueryType: "A",
					Protocol: "udp",
					SourceIP: srcIP,
				}
			}
		}
	}()

	results := pool.Run(runCtx, target, jobs)
	
	collector := metrics.NewCollector(8192)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	doneLoop := false
	for !doneLoop {
		select {
		case <-runCtx.Done():
			doneLoop = true
		case res, ok := <-results:
			if !ok {
				doneLoop = true
				break
			}
			collector.Record(res)
		case <-ticker.C:
			snap := collector.Snapshot(time.Now())
			if snap.TotalQueries > 0 {
				data, _ := json.Marshal(map[string]any{
					"type":           "metric",
					"elapsed":        snap.ElapsedSeconds,
					"qps":            snap.CurrentQPS,
					"total_queries":  snap.TotalQueries,
					"errors":         snap.Errors,
					"loss":           snap.Timeouts,
					"avg_latency_ms": snap.AverageLatencyMS,
					"p50_latency_ms": snap.P50LatencyMS,
					"p99_latency_ms": snap.P99LatencyMS,
				})
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), data)
			}
		}
	}

	if results != nil {
		for res := range results {
			collector.Record(res)
		}
	}

	snap := collector.Snapshot(time.Now())
	score := 100
	if snap.TotalQueries > 0 {
		errorRate := float64(snap.Errors) / float64(snap.TotalQueries)
		score = 100 - int(errorRate*100)
		if score < 0 {
			score = 0
		}
	}

	result := map[string]any{
		"total_queries":  snap.TotalQueries,
		"errors":         snap.Errors,
		"loss":           snap.Timeouts,
		"success":        snap.TotalResponses,
		"avg_latency_ms": snap.AverageLatencyMS,
		"p50_latency_ms": snap.P50LatencyMS,
		"p90_latency_ms": snap.P90LatencyMS,
		"p95_latency_ms": snap.P95LatencyMS,
		"p99_latency_ms": snap.P99LatencyMS,
		"rcodes":         snap.ResponseCodes,
	}

	return score, result, nil
}

// DNS TCP Slowloris / Connection Exhaustion Logic
func (o *Orchestrator) runTCPSlowlorisScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	connections := 20
	if val, ok := config["connections"].(float64); ok && val > 0 {
		connections = int(val)
	}

	holdDuration := 10
	if val, ok := config["hold_duration"].(float64); ok && val > 0 {
		holdDuration = int(val)
	}

	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting TCP Slowloris attack simulation: opening %d concurrent TCP sockets for %d seconds..."}`, connections, holdDuration)))

	if !target.TCPEnabled {
		return 0, nil, fmt.Errorf("target TCP port 53 is disabled in target configuration")
	}

	sockets := make([]net.Conn, 0, connections)
	var mu sync.Mutex
	established := 0
	dropped := 0

	var wg sync.WaitGroup
	for i := 0; i < connections; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", address)
			if err != nil {
				mu.Lock()
				dropped++
				mu.Unlock()
				return
			}

			// Send partial 2-byte DNS length prefix to keep socket open in slow-read mode
			_, _ = conn.Write([]byte{0x00, 0x1d})

			mu.Lock()
			sockets = append(sockets, conn)
			established++
			mu.Unlock()
		}(i)
	}
	wg.Wait()

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[1/2] Sockets opened: %d established, %d failed. Holding connections open..."}`, established, dropped)))

	// Periodically send single heartbeat bytes to prevent immediate idle drop if server doesn't enforce timeout
	stopChan := make(chan struct{})
	go func() {
		ticker := time.NewTicker(2 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stopChan:
				return
			case <-ticker.C:
				mu.Lock()
				for _, conn := range sockets {
					_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
					_, _ = conn.Write([]byte{0x00})
				}
				mu.Unlock()
			}
		}
	}()

	// Sleep for hold duration while keeping connections alive
	time.Sleep(time.Duration(holdDuration) * time.Second)
	close(stopChan)

	// Probe target with a legitimate query while attack sockets are held
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/2] Probing target with legitimate TCP DNS query while attack sockets are held..."}`))

	engine := dnsengine.NewQueryEngine(3 * time.Second)
	probeRes, probeErr := engine.Execute(ctx, target, models.DNSQuery{Domain: "example.com.", QueryType: "A", Protocol: "tcp"})

	legitimateServed := probeErr == nil && probeRes.RCode == 0

	// Close all open attack sockets
	mu.Lock()
	for _, conn := range sockets {
		_ = conn.Close()
	}
	mu.Unlock()

	score := 100
	statusText := "EXCELLENT RESILIENCE"

	if !legitimateServed {
		score -= 50
		statusText = "HIGH VULNERABILITY (DoS DETECTED)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[CRITICAL] Legitimate TCP query was BLOCKED or TIMED OUT during connection exhaustion!"}`))
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target successfully served legitimate TCP query despite socket exhaustion pressure."}`))
	}

	if established == connections {
		score -= 15
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] Target permitted 100%% of slow TCP sockets (%d/%d) without socket timeout."}`, established, connections)))
	}

	if score < 0 {
		score = 0
	}

	probeLatency := any(nil)
	if probeErr == nil {
		probeLatency = probeRes.LatencyMS
	}

	result := map[string]any{
		"connections_requested":  connections,
		"connections_established": established,
		"connections_dropped":    dropped,
		"hold_duration_seconds":  holdDuration,
		"legitimate_tcp_served":  legitimateServed,
		"probe_latency_ms":       probeLatency,
		"status_summary":         statusText,
	}

	return score, result, nil
}

// AXFR Zone Transfer Leak Audit Logic
func (o *Orchestrator) runZoneTransferAuditScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting AXFR Zone Transfer Leak Audit for domain: %s..."}`, domain)))

	if !target.TCPEnabled {
		return 0, nil, fmt.Errorf("target TCP port 53 is disabled in target configuration (AXFR requires TCP)")
	}

	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[1/2] Connecting to %s via TCP 53 and requesting AXFR for %s..."}`, address, domain)))

	records, recordCounts, totalLeaked, transferFailed, errMessage := performAXFR(target, domain, 5*time.Second)

	score := 100
	statusText := "SECURE (TRANSFER REFUSED)"

	if totalLeaked > 0 {
		score = 0
		statusText = "CRITICAL VULNERABILITY (ZONE LEAK DETECTED)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] AXFR Transfer SUCCESSFUL! Leaked %d total zone records for domain %s!"}`, totalLeaked, domain)))
	} else if transferFailed {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] AXFR Transfer refused/failed by target (%s). No records leaked."}`, errMessage)))
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR query returned 0 records. Domain data is protected."}`))
	}

	result := map[string]any{
		"domain":               domain,
		"total_leaked_records": totalLeaked,
		"status_summary":       statusText,
		"record_counts":        recordCounts,
		"sample_records":       records,
	}

	return score, result, nil
}

// DNS Fuzzing & Malformed Packet Test Logic
func (o *Orchestrator) runDNSFuzzingScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"Starting DNS Fuzzing & Malformed Packet Test..."}`))

	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	type fuzzVector struct {
		Category string `json:"category"`
		Name     string `json:"name"`
		Msg      *dns.Msg
		RawBytes []byte
	}

	// 1. Reserved Opcode Fuzzing
	m1 := new(dns.Msg)
	m1.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	m1.Opcode = 6 // Reserved opcode

	// 2. Label Overflow Fuzzing (>63 chars in single label)
	m2 := new(dns.Msg)
	overflowLabel := strings.Repeat("a", 70) + ".example.com."
	m2.SetQuestion(overflowLabel, dns.TypeA)

	// 3. Raw Truncated Header Mutator
	rawMutatedHeader := []byte{0x12, 0x34, 0xff, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// 4. Invalid EDNS0 Option & Version Fuzzing
	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	opt4 := new(dns.OPT)
	opt4.Hdr.Name = "."
	opt4.Hdr.Rrtype = dns.TypeOPT
	opt4.SetUDPSize(4096)
	opt4.SetVersion(15) // Invalid EDNS0 version
	opt4.Option = append(opt4.Option, &dns.EDNS0_LOCAL{Code: 0xffff, Data: []byte("FUZZ_PAYLOAD_DATA")})
	m4.Extra = append(m4.Extra, opt4)

	// 5. Invalid RR Type & Class Fuzzing
	m5 := new(dns.Msg)
	m5.Question = []dns.Question{{Name: dns.Fqdn(domain), Qtype: 0xffff, Qclass: 0xffff}}

	vectors := []fuzzVector{
		{Category: "OPCODE_MUTATION", Name: "Reserved Opcode (6)", Msg: m1},
		{Category: "LABEL_OVERFLOW", Name: "Single Label Overflow (>63 chars)", Msg: m2},
		{Category: "HEADER_CORRUPTION", Name: "Truncated/Corrupted Raw Header Bytes", RawBytes: rawMutatedHeader},
		{Category: "EDNS0_CORRUPTION", Name: "Invalid EDNS0 Version (15) & Custom Local Option", Msg: m4},
		{Category: "CLASS_MUTATION", Name: "Invalid Question Type (0xFFFF) & Class (0xFFFF)", Msg: m5},
	}

	type vectorResult struct {
		Category       string `json:"category"`
		Name           string `json:"name"`
		ResponseStatus string `json:"response_status"`
		HealthCheck    string `json:"health_check"`
	}

	var vectorResults []vectorResult
	engine := dnsengine.NewQueryEngine(2 * time.Second)
	udpClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}

	targetCrashed := false
	score := 100

	for idx, vec := range vectors {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[%d/5] Testing Vector: %s (%s)..."}`, idx+1, vec.Name, vec.Category)))

		respStatus := "NO RESPONSE (DROPPED)"

		if vec.Msg != nil {
			resp, _, err := udpClient.ExchangeContext(ctx, vec.Msg, address)
			if err == nil && resp != nil {
				respStatus = fmt.Sprintf("RCode: %s", dns.RcodeToString[resp.Rcode])
			}
		} else if len(vec.RawBytes) > 0 {
			conn, err := net.DialTimeout("udp", address, 2*time.Second)
			if err == nil {
				_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
				_, _ = conn.Write(vec.RawBytes)
				buf := make([]byte, 512)
				n, errRead := conn.Read(buf)
				if errRead == nil && n > 0 {
					respStatus = fmt.Sprintf("RAW RECV %d BYTES", n)
				}
				_ = conn.Close()
			}
		}

		// Perform post-fuzz health check with valid query
		time.Sleep(200 * time.Millisecond)
		probeRes, probeErr := engine.Execute(ctx, target, models.DNSQuery{Domain: "example.com.", QueryType: "A", Protocol: "udp"})

		healthText := "PASSED (SERVER ALIVE)"
		if probeErr != nil || probeRes.RCode != 0 {
			healthText = "FAILED (PROCESS UNRESPONSIVE)"
			targetCrashed = true
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] Post-fuzz health check FAILED after vector: %s! Server is unresponsive."}`, vec.Name)))
		} else {
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] Post-fuzz health check passed (Latency: %.2f ms)."}`, probeRes.LatencyMS)))
		}

		vectorResults = append(vectorResults, vectorResult{
			Category:       vec.Category,
			Name:           vec.Name,
			ResponseStatus: respStatus,
			HealthCheck:    healthText,
		})
	}

	statusText := "EXCELLENT (CRASH RESILIENT)"
	if targetCrashed {
		score = 0
		statusText = "CRITICAL VULNERABILITY (SERVER CRASH / UNRESPONSIVE)"
	}

	result := map[string]any{
		"domain":            domain,
		"vectors_tested":    len(vectors),
		"target_crashed":    targetCrashed,
		"status_summary":    statusText,
		"fuzzing_results":   vectorResults,
	}

	return score, result, nil
}

// Subdomain Takeover / Dangling CNAME Scanner Logic
func (o *Orchestrator) runSubdomainTakeoverScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	subdomains := []string{"api", "dev", "stage", "blog", "shop", "app", "docs", "status", "mail", "cdn"}
	if rawSubs, ok := config["subdomains"].([]any); ok && len(rawSubs) > 0 {
		subdomains = make([]string, 0, len(rawSubs))
		for _, s := range rawSubs {
			if str, isStr := s.(string); isStr && str != "" {
				subdomains = append(subdomains, str)
			}
		}
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting Subdomain Takeover & Dangling CNAME Scanner for %s (%d subdomains)..."}`, domain, len(subdomains))))

	cloudSignatures := map[string]string{
		"github.io":          "GitHub Pages",
		"s3.amazonaws.com":   "AWS S3 Bucket",
		"herokuapp.com":      "Heroku App",
		"azurewebsites.net":  "Azure Web App",
		"cloudapp.net":       "Azure Cloud App",
		"vercel.app":         "Vercel Deployment",
		"vercel-dns.com":     "Vercel DNS",
		"netlify.app":        "Netlify Site",
		"myshopify.com":      "Shopify Store",
		"wordpress.com":      "WordPress Site",
	}

	type cnameItem struct {
		Subdomain     string `json:"subdomain"`
		CnameTarget   string `json:"cname_target"`
		CloudProvider string `json:"cloud_provider"`
		Status        string `json:"status"`
	}

	var results []cnameItem
	engine := dnsengine.NewQueryEngine(2 * time.Second)
	vulnerableCount := 0
	cnameFoundCount := 0

	udpClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	for idx, sub := range subdomains {
		fqdn := fmt.Sprintf("%s.%s", sub, domain)
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[%d/%d] Scanning %s for CNAME records..."}`, idx+1, len(subdomains), fqdn)))

		// Query CNAME record via dns client
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
		resp, _, err := udpClient.ExchangeContext(ctx, m, address)

		if err == nil && resp != nil && resp.Rcode == dns.RcodeSuccess {
			cnameTarget := ""
			for _, rr := range resp.Answer {
				if cnameRR, ok := rr.(*dns.CNAME); ok {
					cnameTarget = strings.TrimSuffix(cnameRR.Target, ".")
					break
				}
			}

			if cnameTarget != "" {
				cnameFoundCount++
				detectedProvider := "Unknown External"
				for sig, providerName := range cloudSignatures {
					if strings.Contains(strings.ToLower(cnameTarget), sig) {
						detectedProvider = providerName
						break
					}
				}

				// Check if the CNAME target resolves or returns NXDOMAIN/Timeout (Dangling pointer)
				targetRes, targetErr := engine.Execute(ctx, target, models.DNSQuery{Domain: cnameTarget, QueryType: "A", Protocol: "udp"})

				isDangling := targetErr != nil || targetRes.RCode == 3 // NXDOMAIN

				itemStatus := "SAFE (RESOLVING)"
				if isDangling {
					vulnerableCount++
					itemStatus = "VULNERABLE (DANGLING CNAME)"
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] Dangling CNAME detected on %s -> %s (%s)! Target returns NXDOMAIN."}`, fqdn, cnameTarget, detectedProvider)))
				} else {
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] CNAME found for %s -> %s (%s). Target resolves normally."}`, fqdn, cnameTarget, detectedProvider)))
				}

				results = append(results, cnameItem{
					Subdomain:     fqdn,
					CnameTarget:   cnameTarget,
					CloudProvider: detectedProvider,
					Status:        itemStatus,
				})
			}
		}
	}

	score := 100
	statusText := "SECURE (NO DANGLING CNAMEs)"

	if vulnerableCount > 0 {
		score = 100 - (vulnerableCount * 40)
		if score < 0 {
			score = 0
		}
		statusText = fmt.Sprintf("HIGH RISK (%d DANGLING CNAMEs FOUND)", vulnerableCount)
	} else if cnameFoundCount == 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Scan completed. No CNAME records were found for tested subdomains."}`))
	}

	result := map[string]any{
		"domain":             domain,
		"subdomains_scanned": len(subdomains),
		"cnames_found":       cnameFoundCount,
		"vulnerable_count":   vulnerableCount,
		"status_summary":     statusText,
		"scan_results":       results,
	}

	return score, result, nil
}

// Response Rate Limiting (RRL) & SLIP Threshold Test Logic
func (o *Orchestrator) runRRLThresholdScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting Response Rate Limiting (RRL) & SLIP Threshold Test for domain %s..."}`, domain)))

	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	type stageConfig struct {
		Name string
		QPS  int
	}

	stages := []stageConfig{
		{Name: "Stage 1 (Baseline - 25 QPS)", QPS: 25},
		{Name: "Stage 2 (Moderate - 100 QPS)", QPS: 100},
		{Name: "Stage 3 (High - 250 QPS)", QPS: 250},
		{Name: "Stage 4 (Peak Burst - 500 QPS)", QPS: 500},
	}

	type stageResult struct {
		StageName       string  `json:"stage_name"`
		TargetQPS       int     `json:"target_qps"`
		RespondedCount  int     `json:"responded_count"`
		DroppedCount    int     `json:"dropped_count"`
		TruncatedCount  int     `json:"truncated_count"`
		RespondedPct    float64 `json:"responded_pct"`
		DroppedPct      float64 `json:"dropped_pct"`
		TruncatedPct    float64 `json:"truncated_pct"`
		StageResultText string  `json:"stage_result_text"`
	}

	var results []stageResult
	client := &dns.Client{Net: "udp", Timeout: 600 * time.Millisecond}

	detectedThresholdQPS := 0
	slipDetected := false
	rateLimitActive := false

	for idx, stg := range stages {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[%d/4] Testing %s: firing %d UDP burst queries in 1 second..."}`, idx+1, stg.Name, stg.QPS)))

		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		m.RecursionDesired = true

		interval := time.Second / time.Duration(stg.QPS)
		responded := 0
		dropped := 0
		truncated := 0

		var mu sync.Mutex
		var wg sync.WaitGroup

		for i := 0; i < stg.QPS; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				resp, _, err := client.ExchangeContext(ctx, m, address)
				mu.Lock()
				if err != nil {
					dropped++
				} else if resp != nil {
					responded++
					if resp.Truncated {
						truncated++
					}
				}
				mu.Unlock()
			}()
			time.Sleep(interval)
		}
		wg.Wait()

		respPct := float64(int((float64(responded)/float64(stg.QPS))*10000)) / 100
		dropPct := float64(int((float64(dropped)/float64(stg.QPS))*10000)) / 100
		truncPct := float64(int((float64(truncated)/float64(stg.QPS))*10000)) / 100

		stgStatus := "NORMAL (UNLIMITED)"
		if dropPct > 20.0 || truncPct > 0.0 {
			rateLimitActive = true
			if detectedThresholdQPS == 0 {
				detectedThresholdQPS = stg.QPS
			}
			if truncPct > 0.0 {
				slipDetected = true
				stgStatus = "RRL ACTIVE (SLIP TCP FALLBACK)"
			} else {
				stgStatus = "RRL ACTIVE (STRICT DROP)"
			}
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] Rate limit triggered at %d QPS! Dropped: %.1f%%, Truncated (TC=1): %.1f%%"}`, stg.QPS, dropPct, truncPct)))
		} else {
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"- [%s] Responded: %.1f%%, Dropped: %.1f%%"}`, stg.Name, respPct, dropPct)))
		}

		results = append(results, stageResult{
			StageName:       stg.Name,
			TargetQPS:       stg.QPS,
			RespondedCount:  responded,
			DroppedCount:    dropped,
			TruncatedCount:  truncated,
			RespondedPct:    respPct,
			DroppedPct:      dropPct,
			TruncatedPct:    truncPct,
			StageResultText: stgStatus,
		})

		time.Sleep(500 * time.Millisecond)
	}

	score := 100
	statusText := "SECURE (RRL ACTIVE WITH SLIP TCP FALLBACK)"

	if !rateLimitActive {
		score = 50
		statusText = "WARNING (NO RRL RATE LIMITING DETECTED AT 500 QPS)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Target responded to peak 500 QPS burst without enforcing Response Rate Limiting (RRL)."}`))
	} else if slipDetected {
		score = 100
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[EXCELLENT] RRL threshold identified at %d QPS with active SLIP TCP Fallback (TC=1)."}`, detectedThresholdQPS)))
	} else {
		score = 85
		statusText = "GOOD (RRL STRICT DROP ACTIVE)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[GOOD] RRL threshold identified at %d QPS (Strict packet drop)."}`, detectedThresholdQPS)))
	}

	result := map[string]any{
		"domain":                 domain,
		"rate_limit_active":      rateLimitActive,
		"slip_fallback_active":   slipDetected,
		"detected_threshold_qps": detectedThresholdQPS,
		"status_summary":         statusText,
		"stage_results":          results,
	}

	return score, result, nil
}
