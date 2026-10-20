package testrun

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/miekg/dns"

	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

func startAuditDNSServer(t *testing.T, handler dns.Handler) models.Target {
	t.Helper()

	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}
	port := tcpListener.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenPacket("udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		_ = tcpListener.Close()
		t.Fatalf("listen UDP: %v", err)
	}

	tcpServer := &dns.Server{Listener: tcpListener, Net: "tcp", Handler: handler}
	udpServer := &dns.Server{PacketConn: udpConn, Net: "udp", Handler: handler}
	go func() { _ = tcpServer.ActivateAndServe() }()
	go func() { _ = udpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = tcpServer.Shutdown()
		_ = udpServer.Shutdown()
	})

	return models.Target{
		IPAddress:  "127.0.0.1",
		Port:       port,
		UDPEnabled: true,
		TCPEnabled: true,
	}
}

func vulnerableAuditHandler(w dns.ResponseWriter, request *dns.Msg) {
	response := new(dns.Msg)
	response.SetReply(request)

	if len(request.Question) == 0 {
		_ = w.WriteMsg(response)
		return
	}

	question := request.Question[0]
	switch {
	case question.Qtype == dns.TypeAXFR:
		response.Rcode = dns.RcodeRefused
	case question.Name == "google.com." && question.Qtype == dns.TypeA:
		response.RecursionAvailable = true
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
	case question.Name == "version.bind." && question.Qtype == dns.TypeTXT && question.Qclass == dns.ClassCHAOS:
		response.Answer = append(response.Answer, &dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
			Txt: []string{"test-dns 1.0"},
		})
	default:
		response.Rcode = dns.RcodeRefused
	}
	_ = w.WriteMsg(response)
}

func TestSecurityAuditDetectsFindingsAndRefusedAXFR(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(vulnerableAuditHandler))
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	score, result, err := orchestrator.runAuditScenario(
		context.Background(), models.Test{ID: 1}, target, models.ScenarioMetadata{}, map[string]any{"domain": "example.com"},
	)
	if err != nil {
		t.Fatalf("run security audit: %v", err)
	}
	if score != 40 {
		t.Fatalf("score = %d, want 40", score)
	}
	if complete, ok := result["audit_complete"].(bool); !ok || !complete {
		t.Fatalf("audit_complete = %#v, want true", result["audit_complete"])
	}
	if verified := result["verified_checks"]; verified != 3 {
		t.Fatalf("verified_checks = %#v, want 3", verified)
	}

	checks := result["checks"].(map[string]map[string]any)
	if checks["open_recursion"]["status"] != "vulnerable" {
		t.Fatalf("open recursion status = %#v", checks["open_recursion"]["status"])
	}
	if checks["version_disclosure"]["status"] != "vulnerable" {
		t.Fatalf("version disclosure status = %#v", checks["version_disclosure"]["status"])
	}
	if checks["zone_transfer"]["status"] != "secure" {
		t.Fatalf("zone transfer status = %#v", checks["zone_transfer"]["status"])
	}
}

func TestSecurityAuditFailsWhenTargetIsUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	orchestrator := &Orchestrator{hub: ws.NewHub()}
	target := models.Target{IPAddress: "127.0.0.1", Port: port, UDPEnabled: true, TCPEnabled: true}
	score, result, err := orchestrator.runAuditScenario(
		context.Background(), models.Test{ID: 2}, target, models.ScenarioMetadata{}, nil,
	)
	if err == nil {
		t.Fatal("expected unreachable target to fail the security audit")
	}
	if score != 0 || result != nil {
		t.Fatalf("score/result = %d/%#v, want 0/nil", score, result)
	}
}

func TestZoneTransferAuditDistinguishesRefusalFromUnreachable(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(vulnerableAuditHandler))
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	score, result, err := orchestrator.runZoneTransferAuditScenario(
		context.Background(), models.Test{ID: 3}, target, models.ScenarioMetadata{}, map[string]any{"domain": "example.com"},
	)
	if err != nil {
		t.Fatalf("run zone transfer audit: %v", err)
	}
	if score != 100 || result["total_leaked_records"] != 0 {
		t.Fatalf("score/result = %d/%#v, want refused and secure", score, result)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runZoneTransferAuditScenario(
		context.Background(), models.Test{ID: 4}, target, models.ScenarioMetadata{}, nil,
	); err == nil {
		t.Fatal("expected unreachable target to fail the AXFR audit")
	}
}

func TestAmplificationAuditRequiresResponsesAndRunsBurst(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = append(response.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("192.0.2.1"),
		})
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	score, result, err := orchestrator.runAmplificationAuditScenario(
		context.Background(), models.Test{ID: 5}, target, models.ScenarioMetadata{}, nil,
	)
	if err != nil {
		t.Fatalf("run amplification audit: %v", err)
	}
	if score != 75 {
		t.Fatalf("score = %d, want 75 when responses are small but RRL is absent", score)
	}
	if dropped := result["rrl_dropped_count"]; dropped != 0 {
		t.Fatalf("rrl_dropped_count = %#v, want 0", dropped)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runAmplificationAuditScenario(
		context.Background(), models.Test{ID: 6}, target, models.ScenarioMetadata{}, nil,
	); err == nil {
		t.Fatal("expected unreachable target to fail the amplification audit")
	}
}

func TestDNSFuzzingTreatsRefusedResponseAsAlive(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	score, result, err := orchestrator.runDNSFuzzingScenario(
		context.Background(), models.Test{ID: 7}, target, models.ScenarioMetadata{}, nil,
	)
	if err != nil {
		t.Fatalf("run DNS fuzzing audit: %v", err)
	}
	if score != 100 {
		t.Fatalf("score = %d, want 100 for a server that remains responsive", score)
	}
	if crashed := result["target_crashed"]; crashed != false {
		t.Fatalf("target_crashed = %#v, want false", crashed)
	}
}

func TestDNSFuzzingRequiresHealthyBaseline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target := models.Target{IPAddress: "127.0.0.1", Port: closedPort, UDPEnabled: true, TCPEnabled: true}
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	if _, _, err := orchestrator.runDNSFuzzingScenario(
		context.Background(), models.Test{ID: 8}, target, models.ScenarioMetadata{}, nil,
	); err == nil {
		t.Fatal("expected unreachable target to fail the DNS fuzzing baseline")
	}
}

func TestSubdomainTakeoverDistinguishesNXDOMAINFromUnreachable(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}
	config := map[string]any{"domain": "example.com", "subdomains": []string{"api", "www"}}

	score, result, err := orchestrator.runSubdomainTakeoverScenario(
		context.Background(), models.Test{ID: 9}, target, models.ScenarioMetadata{}, config,
	)
	if err != nil {
		t.Fatalf("run subdomain takeover audit: %v", err)
	}
	if score != 100 || result["scan_complete"] != true || result["verified_queries"] != 2 {
		t.Fatalf("unexpected completed scan result: score=%d result=%#v", score, result)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runSubdomainTakeoverScenario(
		context.Background(), models.Test{ID: 10}, target, models.ScenarioMetadata{}, config,
	); err == nil {
		t.Fatal("expected unreachable target to fail the subdomain takeover scan")
	}
}

func TestRRLThresholdRequiresBaselineResponse(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}
	config := map[string]any{"domain": "example.com", "max_burst_qps": float64(1)}

	score, result, err := orchestrator.runRRLThresholdScenario(
		context.Background(), models.Test{ID: 11}, target, models.ScenarioMetadata{}, config,
	)
	if err != nil {
		t.Fatalf("run RRL threshold audit: %v", err)
	}
	if score != 50 || result["rate_limit_active"] != false {
		t.Fatalf("unexpected RRL result: score=%d result=%#v", score, result)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runRRLThresholdScenario(
		context.Background(), models.Test{ID: 12}, target, models.ScenarioMetadata{}, config,
	); err == nil {
		t.Fatal("expected unreachable target to fail the RRL baseline")
	}
}

func TestDNSTunnelingTreatsNXDOMAINAsAcceptedAndErrorsAsUnverified(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}
	config := map[string]any{"domain": "example.com", "payload_bytes": float64(16)}

	score, result, err := orchestrator.runDNSTunnelingScenario(
		context.Background(), models.Test{ID: 13}, target, models.ScenarioMetadata{}, config,
	)
	if err != nil {
		t.Fatalf("run DNS tunneling audit: %v", err)
	}
	if score != 20 || result["delivered_chunks"] != 1 || result["blocked_chunks"] != 0 {
		t.Fatalf("unexpected tunneling result: score=%d result=%#v", score, result)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runDNSTunnelingScenario(
		context.Background(), models.Test{ID: 14}, target, models.ScenarioMetadata{}, config,
	); err == nil {
		t.Fatal("expected unreachable target to fail the DNS tunneling audit")
	}
}

func TestECSAndDNSSECAuditsRequireDNSResponses(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeRefused
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}

	ecsScore, ecsResult, err := orchestrator.runECSManipulationScenario(
		context.Background(), models.Test{ID: 15}, target, models.ScenarioMetadata{}, nil,
	)
	if err != nil {
		t.Fatalf("run ECS audit: %v", err)
	}
	if ecsScore != 90 || ecsResult["verified_queries"] != 5 || ecsResult["audit_complete"] != true {
		t.Fatalf("unexpected ECS result: score=%d result=%#v", ecsScore, ecsResult)
	}

	dnssecScore, dnssecResult, err := orchestrator.runDNSSECAuditScenario(
		context.Background(), models.Test{ID: 16}, target, models.ScenarioMetadata{}, nil,
	)
	if err != nil {
		t.Fatalf("run DNSSEC audit: %v", err)
	}
	if dnssecScore != 50 || dnssecResult["verified_queries"] != 3 || dnssecResult["audit_complete"] != true {
		t.Fatalf("unexpected DNSSEC result: score=%d result=%#v", dnssecScore, dnssecResult)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target.Port = closedPort

	if _, _, err := orchestrator.runECSManipulationScenario(
		context.Background(), models.Test{ID: 17}, target, models.ScenarioMetadata{}, nil,
	); err == nil {
		t.Fatal("expected unreachable target to fail the ECS audit")
	}
	if _, _, err := orchestrator.runDNSSECAuditScenario(
		context.Background(), models.Test{ID: 18}, target, models.ScenarioMetadata{}, nil,
	); err == nil {
		t.Fatal("expected unreachable target to fail the DNSSEC audit")
	}
}

func TestLoadScenariosRunAgainstHealthyDNSBaseline(t *testing.T) {
	target := startAuditDNSServer(t, dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(response)
	}))
	orchestrator := &Orchestrator{hub: ws.NewHub()}
	shortLoad := map[string]any{"qps": float64(5), "workers": float64(2), "duration": float64(1)}

	for _, scenarioID := range []string{"benchmark", "query-flood"} {
		config := map[string]any{
			"qps":         shortLoad["qps"],
			"workers":     shortLoad["workers"],
			"duration":    shortLoad["duration"],
			"query_type":  "A",
			"domain_list": []any{"example.com"},
		}
		score, result, err := orchestrator.runPerformanceScenario(
			context.Background(), models.Test{ID: 20}, target, models.ScenarioMetadata{ID: scenarioID}, config,
		)
		if err != nil {
			t.Fatalf("run %s: %v", scenarioID, err)
		}
		if score != 100 || result["total_queries"].(uint64) == 0 {
			t.Fatalf("unexpected %s result: score=%d result=%#v", scenarioID, score, result)
		}
	}

	rampScore, rampResult, err := orchestrator.runQPSRampScenario(
		context.Background(), models.Test{ID: 21}, target, models.ScenarioMetadata{ID: "qps-ramp"},
		map[string]any{"start_qps": float64(1), "step_qps": float64(1), "max_qps": float64(1), "step_duration": float64(1)},
	)
	if err != nil {
		t.Fatalf("run QPS ramp: %v", err)
	}
	if rampScore != 100 || rampResult["max_qps_reached"] != 1 {
		t.Fatalf("unexpected QPS ramp result: score=%d result=%#v", rampScore, rampResult)
	}

	for _, scenarioID := range []string{"nxdomain", "random-subdomain"} {
		score, result, err := orchestrator.runCacheScenario(
			context.Background(), models.Test{ID: 22}, target, models.ScenarioMetadata{ID: scenarioID},
			map[string]any{"qps": float64(5), "workers": float64(2), "duration": float64(1), "base_domain": "invalid-test.local"},
		)
		if err != nil {
			t.Fatalf("run %s: %v", scenarioID, err)
		}
		if score != 100 || result["total_queries"].(uint64) == 0 {
			t.Fatalf("unexpected %s result: score=%d result=%#v", scenarioID, score, result)
		}
	}

	waterScore, waterResult, err := orchestrator.runWaterTortureScenario(
		context.Background(), models.Test{ID: 23}, target, models.ScenarioMetadata{ID: "water-torture"},
		map[string]any{"qps": float64(5), "workers": float64(2), "duration": float64(1), "domain": "example.com"},
	)
	if err != nil {
		t.Fatalf("run water torture: %v", err)
	}
	if waterScore != 75 || waterResult["total_queries"].(uint64) == 0 {
		t.Fatalf("unexpected water torture result: score=%d result=%#v", waterScore, waterResult)
	}

	slowScore, slowResult, err := orchestrator.runTCPSlowlorisScenario(
		context.Background(), models.Test{ID: 24}, target, models.ScenarioMetadata{ID: "tcp-slowloris"},
		map[string]any{"connections": float64(1), "hold_duration": float64(1)},
	)
	if err != nil {
		t.Fatalf("run TCP slowloris: %v", err)
	}
	if slowScore != 85 || slowResult["legitimate_tcp_served"] != true {
		t.Fatalf("unexpected TCP slowloris result: score=%d result=%#v", slowScore, slowResult)
	}
}

func TestLoadScenariosRejectUnreachableBaseline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	closedPort := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	target := models.Target{IPAddress: "127.0.0.1", Port: closedPort, UDPEnabled: true, TCPEnabled: true}
	orchestrator := &Orchestrator{hub: ws.NewHub()}
	ctx := context.Background()

	checks := []struct {
		name string
		run  func() error
	}{
		{"benchmark", func() error {
			_, _, err := orchestrator.runPerformanceScenario(ctx, models.Test{}, target, models.ScenarioMetadata{ID: "benchmark"}, map[string]any{"duration": float64(1)})
			return err
		}},
		{"qps-ramp", func() error {
			_, _, err := orchestrator.runQPSRampScenario(ctx, models.Test{}, target, models.ScenarioMetadata{ID: "qps-ramp"}, map[string]any{"step_duration": float64(1)})
			return err
		}},
		{"nxdomain", func() error {
			_, _, err := orchestrator.runCacheScenario(ctx, models.Test{}, target, models.ScenarioMetadata{ID: "nxdomain"}, map[string]any{"duration": float64(1)})
			return err
		}},
		{"water-torture", func() error {
			_, _, err := orchestrator.runWaterTortureScenario(ctx, models.Test{}, target, models.ScenarioMetadata{ID: "water-torture"}, map[string]any{"duration": float64(1)})
			return err
		}},
		{"tcp-slowloris", func() error {
			_, _, err := orchestrator.runTCPSlowlorisScenario(ctx, models.Test{}, target, models.ScenarioMetadata{ID: "tcp-slowloris"}, map[string]any{"hold_duration": float64(1)})
			return err
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			if err := check.run(); err == nil {
				t.Fatalf("expected %s to reject unreachable baseline", check.name)
			}
		})
	}
}
