package testrun

import (
	"testing"

	"github.com/dnstrike/dnstrike/internal/scenarios"
)

// TestScenarioHandlerParity guarantees that the scenario metadata catalog and
// the execution handler table never drift apart: every advertised scenario must
// be runnable, and every handler must correspond to a real scenario.
func TestScenarioHandlerParity(t *testing.T) {
	t.Parallel()
	registry := scenarios.DefaultRegistry()

	for _, meta := range registry.List() {
		if _, ok := scenarioHandlers[meta.ID]; !ok {
			t.Errorf("scenario %q is registered in metadata but has no execution handler", meta.ID)
		}
	}

	for id := range scenarioHandlers {
		if _, ok := registry.Get(id); !ok {
			t.Errorf("scenario handler %q has no corresponding metadata entry", id)
		}
	}
}
