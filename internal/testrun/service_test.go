package testrun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/internal/scenarios"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type fakeRepository struct{ item models.Test }

func (f *fakeRepository) CreateTest(_ context.Context, item *models.Test) error {
	item.ID = 7
	item.CreatedAt = time.Now().UTC()
	f.item = *item
	return nil
}
func (f *fakeRepository) ListTests(context.Context, models.TestFilter) ([]models.Test, error) {
	return []models.Test{f.item}, nil
}
func (f *fakeRepository) GetTest(context.Context, int64) (models.Test, error) { return f.item, nil }
func (f *fakeRepository) TransitionTest(_ context.Context, _ int64, _, to models.TestStatus, at time.Time) error {
	f.item.Status = to
	if to == models.TestRunning {
		f.item.StartedAt = &at
	}
	if to.Terminal() {
		f.item.FinishedAt = &at
	}
	return nil
}
func (f *fakeRepository) UpdateTestResult(_ context.Context, _ int64, _ int, _ json.RawMessage) error {
	return nil
}
func (f *fakeRepository) DeleteTest(_ context.Context, _ int64) error {
	return nil
}

type fakeTargets struct{ err error }

func (f fakeTargets) GetTarget(context.Context, int64) (models.Target, error) {
	return models.Target{ID: 1, UDPEnabled: true, TCPEnabled: true}, f.err
}

type fakeScenarios map[string]models.ScenarioMetadata

func (f fakeScenarios) Get(id string) (models.ScenarioMetadata, bool) {
	value, ok := f[id]
	return value, ok
}

func TestCreateTest(t *testing.T) {
	repo := &fakeRepository{}
	service := NewService(repo, fakeTargets{}, fakeScenarios{"benchmark": {ID: "benchmark"}})
	item, err := service.Create(context.Background(), models.CreateTestInput{TargetID: 1, Scenario: " benchmark ", Config: json.RawMessage(`{"qps":100}`)})
	if err != nil {
		t.Fatal(err)
	}
	if item.ID != 7 || item.Status != models.TestPending || item.Scenario != "benchmark" {
		t.Fatalf("unexpected test: %#v", item)
	}
	if string(item.Config) != `{"qps":100}` {
		t.Fatalf("unexpected config: %s", item.Config)
	}
}

func TestCreateMergesDefaultsAndEnforcesLimits(t *testing.T) {
	repo := &fakeRepository{}
	metadata := models.ScenarioMetadata{
		ID: "benchmark", SupportedProtocols: []string{"udp"},
		DefaultConfig:     map[string]any{"qps": 100, "duration": 10, "workers": 4},
		RecommendedLimits: models.Limits{MaxQPS: 500, MaxDuration: 30, MaxWorkers: 16},
	}
	service := NewService(repo, fakeTargets{}, fakeScenarios{"benchmark": metadata})
	item, err := service.Create(context.Background(), models.CreateTestInput{TargetID: 1, Scenario: "benchmark", Config: json.RawMessage(`{"qps":25}`)})
	if err != nil {
		t.Fatal(err)
	}
	var config map[string]any
	if err := json.Unmarshal(item.Config, &config); err != nil {
		t.Fatal(err)
	}
	if config["duration"] != float64(10) || config["workers"] != float64(4) {
		t.Fatalf("defaults were not merged: %s", item.Config)
	}
	_, err = service.Create(context.Background(), models.CreateTestInput{TargetID: 1, Scenario: "benchmark", Config: json.RawMessage(`{"qps":501}`)})
	if err == nil {
		t.Fatal("expected QPS limit rejection")
	}
}

func TestCreateRejectsInvalidSourcePool(t *testing.T) {
	metadata := models.ScenarioMetadata{ID: "benchmark", SupportedProtocols: []string{"udp"}, DefaultConfig: map[string]any{"source_ip_pool": ""}}
	service := NewService(&fakeRepository{}, fakeTargets{}, fakeScenarios{"benchmark": metadata})
	_, err := service.Create(context.Background(), models.CreateTestInput{TargetID: 1, Scenario: "benchmark", Config: json.RawMessage(`{"source_ip_pool":"8.8.8.8"}`)})
	if err == nil {
		t.Fatal("expected public source IP rejection")
	}
}

func TestDefaultScenarioConfigsAreValid(t *testing.T) {
	for _, metadata := range scenarios.DefaultRegistry().List() {
		t.Run(metadata.ID, func(t *testing.T) {
			config := cloneConfig(metadata.DefaultConfig)
			if metadata.ID == "query-flood" {
				config["domain_list"] = []string{"example.test"}
			}
			raw, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := normalizeConfig(raw, metadata); err != nil {
				t.Fatalf("invalid default config: %v", err)
			}
		})
	}
}

func TestCreateRejectsUnknownScenario(t *testing.T) {
	service := NewService(&fakeRepository{}, fakeTargets{}, fakeScenarios{})
	_, err := service.Create(context.Background(), models.CreateTestInput{TargetID: 1, Scenario: "unknown"})
	if err == nil {
		t.Fatal("expected unknown scenario error")
	}
}

func TestCreatePropagatesMissingTarget(t *testing.T) {
	want := errors.New("missing")
	service := NewService(&fakeRepository{}, fakeTargets{err: want}, fakeScenarios{"benchmark": {ID: "benchmark"}})
	_, err := service.Create(context.Background(), models.CreateTestInput{TargetID: 99, Scenario: "benchmark"})
	if !errors.Is(err, want) {
		t.Fatalf("expected target error, got %v", err)
	}
}

func TestTransitionRejectsTerminalTest(t *testing.T) {
	repo := &fakeRepository{item: models.Test{ID: 1, Status: models.TestCompleted}}
	service := NewService(repo, fakeTargets{}, fakeScenarios{})
	_, err := service.Transition(context.Background(), 1, models.TestRunning, time.Now())
	if !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("expected invalid transition, got %v", err)
	}
}
