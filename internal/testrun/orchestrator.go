package testrun

import (
	"context"
	"encoding/json"
	"errors"
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
	transfer.DialTimeout = timeout
	transfer.ReadTimeout = timeout
	transfer.WriteTimeout = timeout

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
		} else if meta.ID == "dns-tunneling" {
			score, result, execErr = o.runDNSTunnelingScenario(ctx, test, target, meta, config)
		} else if meta.ID == "ecs-manipulation" {
			score, result, execErr = o.runECSManipulationScenario(ctx, test, target, meta, config)
		} else if meta.ID == "dnssec-audit" {
			score, result, execErr = o.runDNSSECAuditScenario(ctx, test, target, meta, config)
		} else {
			score, result, execErr = o.runAuditScenario(ctx, test, target, meta, config)
		}
	case "performance", "volume":
		if meta.ID == "tcp-slowloris" {
			score, result, execErr = o.runTCPSlowlorisScenario(ctx, test, target, meta, config)
		} else if meta.ID == "water-torture" {
			score, result, execErr = o.runWaterTortureScenario(ctx, test, target, meta, config)
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
		err = o.tests.SaveResult(ctx, id, score, resultJSON)
	} else {
		err = o.tests.SaveResult(ctx, id, score, []byte("{}"))
	}
	if err != nil {
		slog.Error("orchestrator failed to save result", "test_id", id, "error", err)
		o.failTest(id, "test result could not be saved")
		return
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
	checks := make(map[string]map[string]any, 3)
	verifiedChecks := 0

	// 1. Open Recursion Check
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[1/3] Checking for Open Recursion vulnerability..."}`))
	protocol := scenarioProtocol(target)
	res, err := engine.Execute(ctx, target, models.DNSQuery{Domain: "google.com.", QueryType: "A", Protocol: protocol})
	if err != nil {
		checks["open_recursion"] = map[string]any{"status": "unverified", "error": err.Error()}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Open recursion check could not be verified because the DNS query failed."}`))
	} else if res.RCode == dns.RcodeSuccess && res.RecursionAvailable && res.AnswerCount > 0 {
		verifiedChecks++
		checks["open_recursion"] = map[string]any{"status": "vulnerable", "rcode": res.RCodeName, "recursion_available": true}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Target is an Open Resolver (Recursion enabled for external domains). Vulnerable to DNS Amplification attacks."}`))
		score -= 40
	} else {
		verifiedChecks++
		checks["open_recursion"] = map[string]any{"status": "secure", "rcode": res.RCodeName, "recursion_available": res.RecursionAvailable}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target refused recursion for external domains."}`))
	}

	// 2. Information Leakage (version.bind)
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/3] Checking version.bind CHAOS TXT leakage..."}`))
	res, err = engine.Execute(ctx, target, models.DNSQuery{Domain: "version.bind.", QueryType: "TXT", QueryClass: "CH", Protocol: protocol})
	if err != nil {
		checks["version_disclosure"] = map[string]any{"status": "unverified", "error": err.Error()}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] version.bind disclosure check could not be verified because the DNS query failed."}`))
	} else if res.RCode == dns.RcodeSuccess && res.AnswerCount > 0 {
		verifiedChecks++
		checks["version_disclosure"] = map[string]any{"status": "vulnerable", "rcode": res.RCodeName, "answer_count": res.AnswerCount}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Target leaked software version via CHAOS class query."}`))
		score -= 20
	} else {
		verifiedChecks++
		checks["version_disclosure"] = map[string]any{"status": "secure", "rcode": res.RCodeName, "answer_count": res.AnswerCount}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target did not leak version.bind."}`))
	}

	// 3. AXFR (Zone Transfer)
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[3/3] Attempting AXFR zone transfer for domain: %s"}`, domain)))

	_, recordCounts, leaked, failed, errStr := performAXFR(target, domain, 5*time.Second)
	if !failed && leaked > 0 {
		verifiedChecks++
		checks["zone_transfer"] = map[string]any{"status": "vulnerable", "leaked_records": leaked, "record_counts": recordCounts}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] AXFR Successful! Leaked %d zone records."}`, leaked)))
		score -= 40
	} else if failed && isAXFRRefusal(errStr) {
		verifiedChecks++
		checks["zone_transfer"] = map[string]any{"status": "secure", "error": errStr}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR request was explicitly refused by the target."}`))
	} else if failed {
		checks["zone_transfer"] = map[string]any{"status": "unverified", "error": errStr}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] AXFR check could not be verified because TCP was unavailable or the request timed out."}`))
	} else {
		verifiedChecks++
		checks["zone_transfer"] = map[string]any{"status": "secure", "leaked_records": 0}
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR attempted but no records were returned."}`))
	}

	if score < 0 {
		score = 0
	}
	if verifiedChecks == 0 {
		return 0, nil, errors.New("security audit could not verify any check: DNS target is unreachable")
	}
	complete := verifiedChecks == 3
	statusSummary := "AUDIT COMPLETE"
	if !complete {
		statusSummary = "PARTIAL AUDIT (ONE OR MORE CHECKS UNVERIFIED)"
	}
	result := map[string]any{
		"domain":          domain,
		"checks":          checks,
		"verified_checks": verifiedChecks,
		"total_checks":    3,
		"audit_complete":  complete,
		"status_summary":  statusSummary,
	}
	return score, result, nil
}

func isAXFRRefusal(message string) bool {
	message = strings.ToLower(message)
	return strings.Contains(message, "bad xfr rcode: 5") ||
		strings.Contains(message, "not authoritative")
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
	successfulMeasurements := 0
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
			successfulMeasurements++
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
	if successfulMeasurements == 0 {
		return 0, nil, errors.New("amplification audit could not obtain any DNS response from target")
	}

	// 2. Response Rate Limiting (RRL) Burst Test
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/2] Running 50-query burst test for Response Rate Limiting (RRL)..."}`))

	burstMsg := new(dns.Msg)
	burstMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	burstMsg.RecursionDesired = true

	type burstResult struct {
		dropped   bool
		truncated bool
	}
	burstResults := make(chan burstResult, 50)
	var burstWG sync.WaitGroup
	for i := 0; i < 50; i++ {
		burstWG.Add(1)
		go func() {
			defer burstWG.Done()
			fastClient := &dns.Client{Net: "udp", Timeout: 800 * time.Millisecond}
			resp, _, err := fastClient.ExchangeContext(ctx, burstMsg.Copy(), address)
			burstResults <- burstResult{
				dropped:   err != nil || resp == nil,
				truncated: err == nil && resp != nil && resp.Truncated,
			}
		}()
	}
	burstWG.Wait()
	close(burstResults)

	dropped := 0
	truncated := 0
	for burst := range burstResults {
		if burst.dropped {
			dropped++
		}
		if burst.truncated {
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
	protocol := scenarioProtocol(target)
	if err := verifyDNSBaseline(ctx, target, protocol); err != nil {
		return 0, nil, fmt.Errorf("performance scenario baseline failed: %w", err)
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting benchmark with %d QPS using %d workers for %d seconds..."}`, qps, workers, duration)))

	engine := dnsengine.NewQueryEngine(1 * time.Second)
	pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
		Workers: workers,
		QPS:     qps,
		Burst:   burstSize(qps, 10),
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
						Domain:    domain + ".",
						QueryType: qt,
						Protocol:  protocol,
						SourceIP:  srcIP,
					}
				} else {
					jobs <- models.DNSQuery{
						Domain:    "example.com.",
						QueryType: "A",
						Protocol:  protocol,
						SourceIP:  srcIP,
					}
				}
			}
		}
	}()

	results := pool.Run(runCtx, target, jobs)
	collector := metrics.NewCollector(metrics.DefaultLatencySamples)
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

	// Drain remaining results after context expires
	for res := range results {
		collector.Record(res)
	}

	snap := collector.Snapshot(time.Now())
	if snap.TotalQueries == 0 {
		return 0, nil, errors.New("performance scenario produced no DNS queries")
	}
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
	protocol := scenarioProtocol(target)
	if err := verifyDNSBaseline(ctx, target, protocol); err != nil {
		return 0, nil, fmt.Errorf("QPS ramp baseline failed: %w", err)
	}

	finalScore := 100
	maxStableQPS := 0
	for currentQps <= maxQps {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Testing at %d QPS..."}`, currentQps)))

		pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
			Workers: 50, // Fixed high number for ramp
			QPS:     currentQps,
			Burst:   burstSize(currentQps, 10),
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
						Domain:    "example.com.",
						QueryType: "A",
						Protocol:  protocol,
						SourceIP:  srcIP,
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
				for res := range results {
					stepCollector.Record(res)
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
		if stepTotal == 0 {
			return 0, nil, errors.New("QPS ramp stage produced no DNS queries")
		}

		// Evaluate step
		errorRate := 0.0
		if stepTotal > 0 {
			errorRate = float64(stepErrors) / float64(stepTotal)
		}

		if errorRate > 0.1 { // More than 10% errors
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] Server failed at %d QPS. Error rate: %.2f%%"}`, currentQps, errorRate*100)))
			finalScore = int((float64(maxStableQPS) / float64(maxQps)) * 100)
			break
		}

		maxStableQPS = currentQps
		currentQps += stepQps
	}

	if currentQps > maxQps {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[OK] Target successfully handled max load of %d QPS"}`, maxQps)))
	}

	result := map[string]any{
		"max_qps_reached": maxStableQPS,
	}

	return finalScore, result, nil
}

// Cache Resilience Logic (NXDOMAIN)
func (o *Orchestrator) runCacheScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	protocol := scenarioProtocol(target)
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
	if err := verifyDNSBaseline(ctx, target, protocol); err != nil {
		return 0, nil, fmt.Errorf("cache scenario baseline failed: %w", err)
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
		Burst:   burstSize(qps, 10),
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
					Domain:    fmt.Sprintf("%d.%s.", time.Now().UnixNano(), baseDomain),
					QueryType: "A",
					Protocol:  protocol,
					SourceIP:  srcIP,
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

	// Drain remaining results after context expires
	for res := range results {
		collector.Record(res)
	}

	snap := collector.Snapshot(time.Now())
	if snap.TotalQueries == 0 {
		return 0, nil, errors.New("cache scenario produced no DNS queries")
	}
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
	if err := verifyDNSBaseline(ctx, target, "tcp"); err != nil {
		return 0, nil, fmt.Errorf("TCP slowloris baseline failed: %w", err)
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

	legitimateServed := probeErr == nil

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
		"connections_requested":   connections,
		"connections_established": established,
		"connections_dropped":     dropped,
		"hold_duration_seconds":   holdDuration,
		"legitimate_tcp_served":   legitimateServed,
		"probe_latency_ms":        probeLatency,
		"status_summary":          statusText,
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
	} else if transferFailed && isAXFRRefusal(errMessage) {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR request was explicitly refused by the target. No records leaked."}`))
	} else if transferFailed {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[ERROR] AXFR audit could not reach the target over TCP or timed out."}`))
		return 0, nil, fmt.Errorf("AXFR audit could not be completed: %s", errMessage)
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
	engine := dnsengine.NewQueryEngine(2 * time.Second)
	if _, err := engine.Execute(ctx, target, models.DNSQuery{Domain: domain, QueryType: "A", Protocol: "udp"}); err != nil {
		return 0, nil, fmt.Errorf("DNS fuzzing audit could not establish a healthy baseline: %w", err)
	}

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
		if probeErr != nil {
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
		"domain":          domain,
		"vectors_tested":  len(vectors),
		"target_crashed":  targetCrashed,
		"status_summary":  statusText,
		"fuzzing_results": vectorResults,
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
	if configured, ok := stringSlice(config["subdomains"]); ok && len(configured) > 0 {
		subdomains = configured
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting Subdomain Takeover & Dangling CNAME Scanner for %s (%d subdomains)..."}`, domain, len(subdomains))))

	cloudSignatures := map[string]string{
		"github.io":         "GitHub Pages",
		"s3.amazonaws.com":  "AWS S3 Bucket",
		"herokuapp.com":     "Heroku App",
		"azurewebsites.net": "Azure Web App",
		"cloudapp.net":      "Azure Cloud App",
		"vercel.app":        "Vercel Deployment",
		"vercel-dns.com":    "Vercel DNS",
		"netlify.app":       "Netlify Site",
		"myshopify.com":     "Shopify Store",
		"wordpress.com":     "WordPress Site",
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
	verifiedQueries := 0
	failedQueries := 0

	udpClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))

	for idx, sub := range subdomains {
		fqdn := fmt.Sprintf("%s.%s", sub, domain)
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[%d/%d] Scanning %s for CNAME records..."}`, idx+1, len(subdomains), fqdn)))

		// Query CNAME record via dns client
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCNAME)
		resp, _, err := udpClient.ExchangeContext(ctx, m, address)
		if err != nil || resp == nil {
			failedQueries++
			continue
		}
		verifiedQueries++

		if resp.Rcode == dns.RcodeSuccess {
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

				isDangling := targetErr == nil && targetRes.RCode == dns.RcodeNameError

				itemStatus := "SAFE (RESOLVING)"
				if isDangling {
					vulnerableCount++
					itemStatus = "VULNERABLE (DANGLING CNAME)"
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] Dangling CNAME detected on %s -> %s (%s)! Target returns NXDOMAIN."}`, fqdn, cnameTarget, detectedProvider)))
				} else if targetErr != nil {
					itemStatus = "UNVERIFIED (LOOKUP FAILED)"
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] CNAME target %s could not be verified because its lookup failed."}`, cnameTarget)))
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
	if verifiedQueries == 0 {
		return 0, nil, errors.New("subdomain takeover scan could not obtain any DNS response from target")
	}

	score := 100
	statusText := "SECURE (NO DANGLING CNAMEs)"

	if vulnerableCount > 0 {
		score = 100 - (vulnerableCount * 40)
		if score < 0 {
			score = 0
		}
		statusText = fmt.Sprintf("HIGH RISK (%d DANGLING CNAMEs FOUND)", vulnerableCount)
	} else if failedQueries > 0 {
		statusText = fmt.Sprintf("PARTIAL SCAN (%d OF %d QUERIES UNVERIFIED)", failedQueries, len(subdomains))
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Scan completed partially; one or more subdomain lookups could not be verified."}`))
	} else if cnameFoundCount == 0 {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Scan completed. No CNAME records were found for tested subdomains."}`))
	}

	result := map[string]any{
		"domain":             domain,
		"subdomains_scanned": len(subdomains),
		"cnames_found":       cnameFoundCount,
		"vulnerable_count":   vulnerableCount,
		"verified_queries":   verifiedQueries,
		"unverified_queries": failedQueries,
		"scan_complete":      failedQueries == 0,
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
	baselineClient := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	baselineMsg := new(dns.Msg)
	baselineMsg.SetQuestion(dns.Fqdn(domain), dns.TypeA)
	if response, _, err := baselineClient.ExchangeContext(ctx, baselineMsg, address); err != nil || response == nil {
		return 0, nil, errors.New("RRL threshold audit could not obtain a baseline DNS response from target")
	}

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
	maxBurstQPS := 500
	if value, ok := config["max_burst_qps"].(float64); ok {
		maxBurstQPS = int(value)
	}
	boundedStages := make([]stageConfig, 0, len(stages))
	for _, stage := range stages {
		if stage.QPS <= maxBurstQPS {
			boundedStages = append(boundedStages, stage)
		}
	}
	if len(boundedStages) == 0 || boundedStages[len(boundedStages)-1].QPS != maxBurstQPS {
		boundedStages = append(boundedStages, stageConfig{Name: fmt.Sprintf("Peak Burst - %d QPS", maxBurstQPS), QPS: maxBurstQPS})
	}
	stages = boundedStages

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
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[%d/%d] Testing %s: firing %d UDP burst queries in 1 second..."}`, idx+1, len(stages), stg.Name, stg.QPS)))

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
				resp, _, err := client.ExchangeContext(ctx, m.Copy(), address)
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
		statusText = fmt.Sprintf("WARNING (NO RRL RATE LIMITING DETECTED AT %d QPS)", maxBurstQPS)
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] Target responded to peak %d QPS burst without enforcing Response Rate Limiting (RRL)."}`, maxBurstQPS)))
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

// DNS Covert Tunneling & Exfiltration Audit Logic
func (o *Orchestrator) runDNSTunnelingScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting DNS Covert Tunneling & Exfiltration Audit against domain: %s..."}`, domain)))

	payloadBytes := 256
	if value, ok := config["payload_bytes"].(float64); ok {
		payloadBytes = int(value)
	}
	payloadSeed := "DNStrikeSyntheticAuditPayload_"
	secretPayload := strings.Repeat(payloadSeed, (payloadBytes/len(payloadSeed))+1)[:payloadBytes]
	chunkSize := 16
	var chunks []string
	for i := 0; i < len(secretPayload); i += chunkSize {
		end := i + chunkSize
		if end > len(secretPayload) {
			end = len(secretPayload)
		}
		chunks = append(chunks, fmt.Sprintf("%x", secretPayload[i:end]))
	}

	engine := dnsengine.NewQueryEngine(2 * time.Second)
	sentChunks := 0
	blockedChunks := 0
	unverifiedChunks := 0
	totalBytes := 0

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[1/2] Transmitting %d hex-encoded covert data chunks in subdomain queries..."}`, len(chunks))))

	for idx, chunk := range chunks {
		subdomain := fmt.Sprintf("chunk%d-%s.%s.", idx, chunk, domain)
		q := models.DNSQuery{Domain: subdomain, QueryType: "TXT", Protocol: "udp"}
		res, err := engine.Execute(ctx, target, q)
		totalBytes += len(chunk) / 2

		if err != nil {
			unverifiedChunks++
		} else if res.RCode == dns.RcodeRefused {
			blockedChunks++
		} else {
			// NXDOMAIN still proves that the resolver accepted and processed the
			// encoded name; it is not evidence of a DLP/firewall block.
			sentChunks++
		}
		time.Sleep(100 * time.Millisecond)
	}
	if unverifiedChunks == len(chunks) {
		return 0, nil, errors.New("DNS tunneling audit could not obtain any DNS response from target")
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[2/2] Exfiltration summary: %d/%d chunks accepted, %d refused, %d unverified."}`, sentChunks, len(chunks), blockedChunks, unverifiedChunks)))

	score := 100
	statusText := "SECURE (COVERT TUNNELING BLOCKED)"

	if sentChunks == len(chunks) {
		score = 20
		statusText = "HIGH RISK (ALL COVERT QUERIES ACCEPTED BY RESOLVER)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[CRITICAL] All covert DNS names were accepted by the resolver; authoritative delivery requires external telemetry to confirm."}`))
	} else if sentChunks > 0 {
		score = 60
		statusText = "MEDIUM RISK (SOME COVERT QUERIES ACCEPTED)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WARNING] Some covert DNS names were accepted (%d/%d); authoritative delivery is not proven."}`, sentChunks, len(chunks))))
	} else if unverifiedChunks > 0 {
		statusText = "PARTIAL AUDIT (RESPONSES UNVERIFIED)"
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Covert tunneling queries were explicitly refused by the DNS target."}`))
	}

	result := map[string]any{
		"domain":            domain,
		"total_chunks":      len(chunks),
		"delivered_chunks":  sentChunks,
		"blocked_chunks":    blockedChunks,
		"unverified_chunks": unverifiedChunks,
		"total_bytes_sent":  totalBytes,
		"entropy_rating":    "HIGH (HEX ENCODED)",
		"status_summary":    statusText,
	}

	return score, result, nil
}

// Water Torture (Random Subdomain NXDOMAIN Flood) Logic
func (o *Orchestrator) runWaterTortureScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}
	qps := 200
	if val, ok := config["qps"].(float64); ok && val > 0 {
		qps = int(val)
	}
	durationSec := 15
	if val, ok := config["duration"].(float64); ok && val > 0 {
		durationSec = int(val)
	}

	workers := 20
	if val, ok := config["workers"].(float64); ok && val > 0 {
		workers = int(val)
	}
	protocol := scenarioProtocol(target)
	if err := verifyDNSBaseline(ctx, target, protocol); err != nil {
		return 0, nil, fmt.Errorf("water torture baseline failed: %w", err)
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting Water Torture (Random Subdomain NXDOMAIN Flood) against %s at %d QPS for %ds..."}`, domain, qps, durationSec)))

	engine := dnsengine.NewQueryEngine(2 * time.Second)
	pool, err := dnsengine.NewWorkerPool(engine, dnsengine.PoolConfig{
		Workers: workers,
		QPS:     qps,
		Burst:   burstSize(qps, 5),
	})
	if err != nil {
		return 0, nil, err
	}

	runCtx, cancelRun := context.WithTimeout(ctx, time.Duration(durationSec)*time.Second)
	defer cancelRun()

	jobs := make(chan models.DNSQuery)
	go func() {
		defer close(jobs)
		var sourceIPs []string
		if val, ok := config["_parsed_source_ips"].([]string); ok {
			sourceIPs = val
		}
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
				randLabel := fmt.Sprintf("rand-%d-%d", time.Now().UnixNano(), ipIdx)
				jobs <- models.DNSQuery{
					Domain:    fmt.Sprintf("%s.%s.", randLabel, domain),
					QueryType: "A",
					Protocol:  protocol,
					SourceIP:  srcIP,
				}
			}
		}
	}()

	results := pool.Run(runCtx, target, jobs)
	collector := metrics.NewCollector(8192)

	for res := range results {
		collector.Record(res)
	}

	snap := collector.Snapshot(time.Now())
	if snap.TotalQueries == 0 {
		return 0, nil, errors.New("water torture scenario produced no DNS queries")
	}
	nxdomainCount := snap.ResponseCodes["NXDOMAIN"]
	refusedCount := snap.ResponseCodes["REFUSED"]

	score := 100
	statusText := "EXCELLENT RESILIENCE (RECURSION REFUSED / BOUNDED)"

	if snap.TotalQueries > 0 {
		errorRate := float64(snap.Errors) / float64(snap.TotalQueries)
		if errorRate > 0.30 {
			score = 40
			statusText = "HIGH VULNERABILITY (HIGH ERROR/DROPPED RATE DURING NXDOMAIN FLOOD)"
		} else if nxdomainCount > 0 {
			score = 75
			statusText = "MODERATE (UPSTREAM AUTHORITATIVE PRESSURE DETECTED)"
		}
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[WATER TORTURE COMPLETE] Queries: %d, NXDOMAIN: %d, Refused: %d, Timeouts: %d, Avg Latency: %.2fms"}`, snap.TotalQueries, nxdomainCount, refusedCount, snap.Timeouts, snap.AverageLatencyMS)))

	result := map[string]any{
		"target_domain":  domain,
		"total_queries":  snap.TotalQueries,
		"nxdomain_count": nxdomainCount,
		"refused_count":  refusedCount,
		"timeouts":       snap.Timeouts,
		"avg_latency_ms": snap.AverageLatencyMS,
		"p99_latency_ms": snap.P99LatencyMS,
		"status_summary": statusText,
	}

	return score, result, nil
}

func burstSize(qps, divisor int) int {
	burst := qps / divisor
	if burst < 1 {
		return 1
	}
	return burst
}

func scenarioProtocol(target models.Target) string {
	if target.UDPEnabled {
		return "udp"
	}
	return "tcp"
}

func verifyDNSBaseline(ctx context.Context, target models.Target, protocol string) error {
	engine := dnsengine.NewQueryEngine(2 * time.Second)
	_, err := engine.Execute(ctx, target, models.DNSQuery{
		Domain:    "example.com.",
		QueryType: "A",
		Protocol:  protocol,
	})
	if err != nil {
		return errors.New("target did not return a DNS response")
	}
	return nil
}

// EDNS0 Client Subnet (ECS) Geo-Spoofing Audit Logic
func (o *Orchestrator) runECSManipulationScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting EDNS0 Client Subnet (ECS) Geo-Spoofing Audit for domain: %s..."}`, domain)))

	type geoSubnet struct {
		Region string
		Subnet string
	}

	subnets := []geoSubnet{
		{Region: "US East (Virginia)", Subnet: "8.8.8.0"},
		{Region: "Europe (Frankfurt)", Subnet: "194.12.200.0"},
		{Region: "Asia (Tokyo)", Subnet: "210.140.0.0"},
		{Region: "South America (Brazil)", Subnet: "200.160.0.0"},
		{Region: "Global IPv6", Subnet: "2001:4860:4860::"},
	}

	engine := dnsengine.NewQueryEngine(3 * time.Second)
	protocol := scenarioProtocol(target)
	ecsSupported := false
	geoAnswers := make(map[string]string)
	verifiedQueries := 0
	unverifiedQueries := 0

	for _, s := range subnets {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Injecting ECS Option: %s (%s)..."}`, s.Region, s.Subnet)))
		q := models.DNSQuery{
			Domain:       domain,
			QueryType:    "A",
			Protocol:     protocol,
			ClientSubnet: s.Subnet,
		}
		res, err := engine.Execute(ctx, target, q)
		if err == nil {
			verifiedQueries++
		} else {
			unverifiedQueries++
			geoAnswers[s.Region] = "Unverified (query failed)"
			continue
		}
		if res.RCode == dns.RcodeSuccess {
			if res.ECSResponse {
				ecsSupported = true
				geoAnswers[s.Region] = fmt.Sprintf("ECS echoed, RCode: %s (%dms)", res.RCodeName, int(res.LatencyMS))
			} else {
				geoAnswers[s.Region] = fmt.Sprintf("Response received; ECS not echoed (%dms)", int(res.LatencyMS))
			}
		} else {
			geoAnswers[s.Region] = fmt.Sprintf("Response received; RCode: %s", res.RCodeName)
		}
	}
	if verifiedQueries == 0 {
		return 0, nil, errors.New("ECS audit could not obtain any DNS response from target")
	}

	score := 100
	statusText := "SECURE (ECS OPTION HANDLED / PRIVACY RESPECTED)"

	if ecsSupported {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target DNS server processed queries containing EDNS0 Client Subnet options."}`))
	} else {
		score = 90
		statusText = "NOTICE (ECS OPTION NOT REFLECTED OR STRIPPED)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[NOTE] Target DNS server stripped or ignored ECS options (privacy protection active)."}`))
	}
	if unverifiedQueries > 0 {
		statusText = fmt.Sprintf("PARTIAL ECS AUDIT (%d OF %d QUERIES UNVERIFIED)", unverifiedQueries, len(subnets))
	}

	result := map[string]any{
		"domain":             domain,
		"ecs_supported":      ecsSupported,
		"verified_queries":   verifiedQueries,
		"unverified_queries": unverifiedQueries,
		"audit_complete":     unverifiedQueries == 0,
		"geo_responses":      geoAnswers,
		"status_summary":     statusText,
	}

	return score, result, nil
}

// DNSSEC Cryptographic & Health Audit Logic
func (o *Orchestrator) runDNSSECAuditScenario(ctx context.Context, test models.Test, target models.Target, meta models.ScenarioMetadata, config map[string]any) (int, map[string]any, error) {
	domain := "example.com"
	if val, ok := config["domain"].(string); ok && val != "" {
		domain = val
	}

	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"Starting DNSSEC Cryptographic & Health Audit for domain: %s..."}`, domain)))

	engine := dnsengine.NewQueryEngine(3 * time.Second)
	protocol := scenarioProtocol(target)

	// 1. Query DNSKEY with DO bit
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[1/3] Querying DNSKEY records with DO (DNSSEC OK) flag..."}`))
	keyRes, keyErr := engine.Execute(ctx, target, models.DNSQuery{Domain: domain, QueryType: "DNSKEY", Protocol: protocol, DNSSECOK: true})

	// 2. Query DS record
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[2/3] Querying DS (Delegation Signer) records..."}`))
	dsRes, dsErr := engine.Execute(ctx, target, models.DNSQuery{Domain: domain, QueryType: "DS", Protocol: protocol, DNSSECOK: true})

	// 3. Query SOA RRSIG
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[3/3] Querying SOA RRSIG cryptographic signatures..."}`))
	soaRes, soaErr := engine.Execute(ctx, target, models.DNSQuery{Domain: domain, QueryType: "SOA", Protocol: protocol, DNSSECOK: true})
	verifiedQueries := 0
	for _, queryErr := range []error{keyErr, dsErr, soaErr} {
		if queryErr == nil {
			verifiedQueries++
		}
	}
	if verifiedQueries == 0 {
		return 0, nil, errors.New("DNSSEC audit could not obtain any DNS response from target")
	}

	hasDNSKEY := keyErr == nil && containsString(keyRes.AnswerTypes, "DNSKEY")
	hasDS := dsErr == nil && containsString(dsRes.AnswerTypes, "DS")
	hasRRSIG := soaErr == nil && containsString(soaRes.AnswerTypes, "RRSIG")

	score := 100
	statusText := "DNSSEC RECORDS PRESENT"

	if !hasDNSKEY && !hasDS {
		score = 50
		statusText = "NOTICE (DNSSEC NOT SIGNED FOR DOMAIN)"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[NOTICE] Target domain is not signed with DNSSEC (No DNSKEY/DS records returned)."} `))
	} else if hasDNSKEY && hasRRSIG {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] Target returned DNSKEY and RRSIG records. Cryptographic validation is outside this presence check."}`))
	} else {
		score = 75
		statusText = "PARTIAL DNSSEC IMPLEMENTATION"
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[WARNING] Partial DNSSEC records detected."}`))
	}

	result := map[string]any{
		"domain":           domain,
		"dnskey_present":   hasDNSKEY,
		"ds_present":       hasDS,
		"rrsig_present":    hasRRSIG,
		"verified_queries": verifiedQueries,
		"audit_complete":   verifiedQueries == 3,
		"status_summary":   statusText,
	}

	return score, result, nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
