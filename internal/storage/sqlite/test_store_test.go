package sqlite

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
)

func TestTestLifecyclePersistence(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	target := models.Target{Name: "Local DNS", IPAddress: "127.0.0.1", Port: 5353, UDPEnabled: true, Tags: []string{}}
	if err := store.CreateTarget(ctx, &target); err != nil {
		t.Fatal(err)
	}
	testRun := models.Test{TargetID: target.ID, Scenario: "benchmark", Status: models.TestPending, Config: json.RawMessage(`{"qps":50}`)}
	if err := store.CreateTest(ctx, &testRun); err != nil {
		t.Fatal(err)
	}
	if testRun.ID < 1 || testRun.CreatedAt.IsZero() {
		t.Fatalf("test identity not assigned: %#v", testRun)
	}
	items, err := store.ListTests(ctx, models.TestFilter{TargetID: target.ID, Status: models.TestPending})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].ID != testRun.ID {
		t.Fatalf("unexpected list: %#v", items)
	}
	started := time.Date(2026, 8, 31, 10, 0, 0, 0, time.UTC)
	if err := store.TransitionTest(ctx, testRun.ID, models.TestPending, models.TestRunning, started); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionTest(ctx, testRun.ID, models.TestRunning, models.TestCompleted, started.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	got, err := store.GetTest(ctx, testRun.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != models.TestCompleted || got.StartedAt == nil || got.FinishedAt == nil || got.DurationSeconds != 3 {
		t.Fatalf("unexpected persisted lifecycle: %#v", got)
	}
}

func TestTransitionUsesOptimisticStatus(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	target := models.Target{Name: "DNS", IPAddress: "127.0.0.1", Port: 5353, UDPEnabled: true}
	if err := store.CreateTarget(ctx, &target); err != nil {
		t.Fatal(err)
	}
	testRun := models.Test{TargetID: target.ID, Scenario: "benchmark", Status: models.TestPending, Config: json.RawMessage(`{}`)}
	if err := store.CreateTest(ctx, &testRun); err != nil {
		t.Fatal(err)
	}
	if err := store.TransitionTest(ctx, testRun.ID, models.TestRunning, models.TestCompleted, time.Now()); err != ErrNotFound {
		t.Fatalf("expected optimistic transition rejection, got %v", err)
	}
}
