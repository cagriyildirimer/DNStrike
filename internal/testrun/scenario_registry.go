package testrun

import (
	"context"

	"github.com/dnstrike/dnstrike/pkg/models"
)

// scenarioHandler executes a single scenario and returns its resilience score,
// a JSON-serializable result map, and an error. The signature deliberately
// matches the run*Scenario methods on *Orchestrator, so each method can be
// registered directly as a method expression (no adapter closures needed).
type scenarioHandler func(*Orchestrator, context.Context, models.Test, models.Target, models.ScenarioMetadata, map[string]any) (int, map[string]any, error)

// scenarioHandlers is the single registration point for scenario execution.
//
// To add a new scenario:
//  1. register its metadata in scenarios.DefaultRegistry (the catalog shown to
//     the API/UI and used for config validation), and
//  2. add one entry here mapping its ID to the method that runs it.
//
// TestScenarioHandlerParity fails the build if a metadata entry has no handler
// or a handler has no metadata, so the two sources can never silently drift.
var scenarioHandlers = map[string]scenarioHandler{
	// audit
	"security-audit":      (*Orchestrator).runAuditScenario,
	"zone-transfer-audit": (*Orchestrator).runZoneTransferAuditScenario,
	"amplification-audit": (*Orchestrator).runAmplificationAuditScenario,
	"dns-fuzzing":         (*Orchestrator).runDNSFuzzingScenario,
	"subdomain-takeover":  (*Orchestrator).runSubdomainTakeoverScenario,
	"rrl-threshold":       (*Orchestrator).runRRLThresholdScenario,
	"dns-tunneling":       (*Orchestrator).runDNSTunnelingScenario,
	"ecs-manipulation":    (*Orchestrator).runECSManipulationScenario,
	"dnssec-audit":        (*Orchestrator).runDNSSECAuditScenario,
	// performance
	"benchmark": (*Orchestrator).runPerformanceScenario,
	"qps-ramp":  (*Orchestrator).runQPSRampScenario,
	// resolver-cache
	"nxdomain":         (*Orchestrator).runCacheScenario,
	"random-subdomain": (*Orchestrator).runCacheScenario,
	// volume
	"query-flood":   (*Orchestrator).runPerformanceScenario,
	"water-torture": (*Orchestrator).runWaterTortureScenario,
	"tcp-slowloris": (*Orchestrator).runTCPSlowlorisScenario,
}
