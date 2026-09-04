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
	"github.com/dnstrike/dnstrike/internal/scenarios"
	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

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
		score, result, execErr = o.runAuditScenario(ctx, test, target, meta, config)
	case "performance", "volume":
		score, result, execErr = o.runPerformanceScenario(ctx, test, target, meta, config)
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
	o.hub.Broadcast(fmt.Sprintf("%d", id), []byte(fmt.Sprintf(`{"type":"failed","reason":"%s"}`, reason)))
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
	if val, ok := config["domain"].(string); ok {
		domain = val
	}
	
	o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[3/3] Attempting AXFR zone transfer for domain: %s"}`, domain)))
	
	if target.TCPEnabled {
		transfer := new(dns.Transfer)
		address := net.JoinHostPort(target.IPAddress, fmt.Sprintf("%d", target.Port))
		m := new(dns.Msg)
		m.SetAxfr(dns.Fqdn(domain))
		
		ch, err := transfer.In(m, address)
		if err == nil {
			leaked := 0
			for env := range ch {
				if env.Error == nil {
					leaked += len(env.RR)
				}
			}
			if leaked > 0 {
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(fmt.Sprintf(`{"type":"log","message":"[CRITICAL] AXFR Successful! Leaked %d zone records."}`, leaked)))
				score -= 40
			} else {
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR attempted but no records were returned."}`))
			}
		} else {
			o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[OK] AXFR connection refused or timed out."}`))
		}
	} else {
		o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(`{"type":"log","message":"[SKIPPED] AXFR requires TCP, which is disabled on this target."}`))
	}

	if score < 0 {
		score = 0
	}
	return score, nil, nil
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
	
	var total, errors, loss int
	var latencyTotal float64

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			// Drain remaining
			for range results {}
			score := 100
			if total > 0 {
				errorRate := float64(errors) / float64(total)
				score = 100 - int(errorRate*100)
			}
			result := map[string]any{
				"total_queries": total,
				"errors": errors,
				"loss": loss,
				"success": total - errors,
			}
			if total > 0 {
				result["avg_latency_ms"] = latencyTotal / float64(total)
			}
			return score, result, nil
		case res, ok := <-results:
			if !ok {
				continue
			}
			total++
			latencyTotal += res.LatencyMS
			if res.ErrorClass != "" {
				errors++
				if res.ErrorClass == models.QueryTimeout {
					loss++
				}
			}
		case <-ticker.C:
			// Send realtime metric snapshot
			if total > 0 {
				avg := latencyTotal / float64(total)
				snap := fmt.Sprintf(`{"type":"metric","elapsed":1,"qps":%d,"errors":%d,"loss":%d,"avg_latency_ms":%.2f}`, total, errors, loss, avg)
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(snap))
			}
		}
	}
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
		
		var stepTotal, stepErrors, stepLoss int
		var latencyTotal float64

		ticker := time.NewTicker(1 * time.Second)
		
	drainLoop:
		for {
			select {
			case <-stepCtx.Done():
				ticker.Stop()
				cancel()
				// Drain remaining
				for range results {
					stepTotal++
				}
				break drainLoop
			case res, ok := <-results:
				if !ok {
					continue
				}
				stepTotal++
				latencyTotal += res.LatencyMS
				if res.ErrorClass != "" {
					stepErrors++
					if res.ErrorClass == models.QueryTimeout {
						stepLoss++
					}
				}
			case <-ticker.C:
				if stepTotal > 0 {
					avg := latencyTotal / float64(stepTotal)
					snap := fmt.Sprintf(`{"type":"metric","elapsed":1,"qps":%d,"errors":%d,"loss":%d,"avg_latency_ms":%.2f}`, stepTotal, stepErrors, stepLoss, avg)
					o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(snap))
				}
			}
		}
		
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
	
	var total, errors, loss int
	var latencyTotal float64

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-runCtx.Done():
			for range results {}
			score := 100
			if total > 0 {
				errorRate := float64(errors) / float64(total)
				score = 100 - int(errorRate*100)
			}
			result := map[string]any{
				"total_queries": total,
				"errors": errors,
				"loss": loss,
				"success": total - errors,
			}
			if total > 0 {
				result["avg_latency_ms"] = latencyTotal / float64(total)
			}
			return score, result, nil
		case res, ok := <-results:
			if !ok {
				continue
			}
			total++
			latencyTotal += res.LatencyMS
			if res.ErrorClass != "" {
				errors++
				if res.ErrorClass == models.QueryTimeout {
					loss++
				}
			}
		case <-ticker.C:
			if total > 0 {
				avg := latencyTotal / float64(total)
				snap := fmt.Sprintf(`{"type":"metric","elapsed":1,"qps":%d,"errors":%d,"loss":%d,"avg_latency_ms":%.2f}`, total, errors, loss, avg)
				o.hub.Broadcast(fmt.Sprintf("%d", test.ID), []byte(snap))
			}
		}
	}
}
