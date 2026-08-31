package testrun

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

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

type fakeTargets struct{ err error }

func (f fakeTargets) GetTarget(context.Context, int64) (models.Target, error) {
	return models.Target{ID: 1}, f.err
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
