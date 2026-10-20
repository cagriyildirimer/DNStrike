package dnsengine

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/dnstrike/dnstrike/internal/limiter"
	"github.com/dnstrike/dnstrike/pkg/models"
)

type Executor interface {
	Execute(context.Context, models.Target, models.DNSQuery) (models.QueryResult, error)
}
type PoolConfig struct {
	Workers int
	QPS     int
	Burst   int
}
type WorkerPool struct {
	executor Executor
	config   PoolConfig
}

func NewWorkerPool(executor Executor, config PoolConfig) (*WorkerPool, error) {
	if executor == nil {
		return nil, errors.New("DNS query executor is required")
	}
	if config.Workers < 1 || config.Workers > 256 {
		return nil, errors.New("number of workers must be between 1 and 256")
	}
	if config.Burst == 0 {
		config.Burst = 1
	}
	if _, err := limiter.NewTokenBucket(config.QPS, config.Burst); err != nil {
		return nil, err
	}
	return &WorkerPool{executor: executor, config: config}, nil
}

func (p *WorkerPool) Run(ctx context.Context, target models.Target, jobs <-chan models.DNSQuery) <-chan models.QueryResult {
	results := make(chan models.QueryResult, p.config.Workers*2)
	bucket, _ := limiter.NewTokenBucket(p.config.QPS, p.config.Burst)
	var workers sync.WaitGroup
	workers.Add(p.config.Workers)
	for i := 0; i < p.config.Workers; i++ {
		go func() {
			defer workers.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case query, ok := <-jobs:
					if !ok {
						return
					}
					if err := bucket.Wait(ctx); err != nil {
						return
					}
					result, _ := p.executor.Execute(ctx, target, query)
					// The scenario deadline is a load-generator boundary, not a target
					// failure. Do not count an in-flight query cancelled by that boundary.
					deadline, hasDeadline := ctx.Deadline()
					if ctx.Err() != nil || (hasDeadline && !time.Now().Before(deadline)) {
						return
					}
					select {
					case results <- result:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() { workers.Wait(); close(results) }()
	return results
}
