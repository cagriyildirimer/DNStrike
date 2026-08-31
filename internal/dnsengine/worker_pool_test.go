package dnsengine

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
)

type concurrencyExecutor struct {
	active  atomic.Int32
	maximum atomic.Int32
}

func (e *concurrencyExecutor) Execute(ctx context.Context, _ models.Target, q models.DNSQuery) (models.QueryResult, error) {
	active := e.active.Add(1)
	defer e.active.Add(-1)
	for {
		maximum := e.maximum.Load()
		if active <= maximum || e.maximum.CompareAndSwap(maximum, active) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return models.QueryResult{ErrorClass: models.QueryCancelled}, ctx.Err()
	case <-time.After(5 * time.Millisecond):
		return models.QueryResult{Domain: q.Domain}, nil
	}
}

func TestWorkerPoolBoundsConcurrencyAndDrains(t *testing.T) {
	executor := &concurrencyExecutor{}
	pool, err := NewWorkerPool(executor, PoolConfig{Workers: 3, QPS: 10000, Burst: 20})
	if err != nil {
		t.Fatal(err)
	}
	jobs := make(chan models.DNSQuery, 20)
	for i := 0; i < 20; i++ {
		jobs <- models.DNSQuery{Domain: "example.test"}
	}
	close(jobs)
	count := 0
	for range pool.Run(context.Background(), models.Target{}, jobs) {
		count++
	}
	if count != 20 {
		t.Fatalf("got %d results", count)
	}
	if executor.maximum.Load() > 3 {
		t.Fatalf("worker bound exceeded: %d", executor.maximum.Load())
	}
}

func TestWorkerPoolStopsOnContextCancellation(t *testing.T) {
	executor := &concurrencyExecutor{}
	pool, err := NewWorkerPool(executor, PoolConfig{Workers: 2, QPS: 1, Burst: 1})
	if err != nil {
		t.Fatal(err)
	}
	jobs := make(chan models.DNSQuery, 10)
	for i := 0; i < 10; i++ {
		jobs <- models.DNSQuery{}
	}
	close(jobs)
	ctx, cancel := context.WithCancel(context.Background())
	results := pool.Run(ctx, models.Target{}, jobs)
	cancel()
	select {
	case _, ok := <-results:
		if ok {
			for range results {
			}
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("workers did not stop after cancellation")
	}
}
