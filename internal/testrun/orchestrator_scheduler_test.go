package testrun

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	ws "github.com/dnstrike/dnstrike/internal/websocket"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type schedulerRepository struct {
	mu    sync.Mutex
	items map[int64]models.Test
}

func newSchedulerRepository(count int) *schedulerRepository {
	items := make(map[int64]models.Test, count)
	for index := 1; index <= count; index++ {
		id := int64(index)
		items[id] = models.Test{ID: id, TargetID: 1, Scenario: "benchmark", Status: models.TestPending, Config: json.RawMessage(`{}`)}
	}
	return &schedulerRepository{items: items}
}

func (r *schedulerRepository) EnqueueTest(context.Context, *models.Test, int) (bool, error) {
	return true, nil
}

func (r *schedulerRepository) ListTests(_ context.Context, filter models.TestFilter) ([]models.Test, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := make([]models.Test, 0, filter.Limit)
	for id := int64(1); id <= int64(len(r.items)) && len(items) < filter.Limit; id++ {
		item := r.items[id]
		if filter.Status == "" || item.Status == filter.Status {
			items = append(items, item)
		}
	}
	return items, nil
}

func (r *schedulerRepository) GetTest(_ context.Context, id int64) (models.Test, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.items[id], nil
}

func (r *schedulerRepository) TransitionTest(_ context.Context, id int64, from, to models.TestStatus, at time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	item := r.items[id]
	if item.Status != from {
		return ErrInvalidTransition
	}
	item.Status = to
	if to == models.TestRunning {
		item.StartedAt = &at
	}
	r.items[id] = item
	return nil
}

func (r *schedulerRepository) UpdateTestResult(context.Context, int64, int, json.RawMessage) error {
	return nil
}

func (r *schedulerRepository) DeleteTest(context.Context, int64) error { return nil }

func TestOrchestratorHonorsGlobalConcurrencyLimit(t *testing.T) {
	repository := newSchedulerRepository(5)
	service := NewService(repository, nil, nil)
	orchestrator := NewOrchestrator(service, nil, nil, ws.NewHub(), 2)
	started := make(chan int64, 5)
	release := make(chan struct{})
	orchestrator.run = func(test models.Test) {
		started <- test.ID
		<-release
	}

	orchestrator.pollPending()
	for count := 0; count < 2; count++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("timed out waiting for scheduled test")
		}
	}
	orchestrator.pollPending()
	select {
	case id := <-started:
		t.Fatalf("test %d started above the concurrency limit", id)
	case <-time.After(100 * time.Millisecond):
	}

	close(release)
	deadline := time.Now().Add(time.Second)
	for len(orchestrator.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(orchestrator.slots) != 0 {
		t.Fatal("worker slots were not released")
	}
}
