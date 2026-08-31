package limiter

import (
	"context"
	"errors"
	"sync"
	"time"
)

type TokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func NewTokenBucket(qps, burst int) (*TokenBucket, error) {
	if qps < 1 || qps > 10_000 {
		return nil, errors.New("QPS 1 ile 10000 arasında olmalıdır")
	}
	if burst < 1 || burst > qps {
		return nil, errors.New("burst 1 ile QPS arasında olmalıdır")
	}
	now := time.Now()
	return &TokenBucket{rate: float64(qps), capacity: float64(burst), tokens: float64(burst), last: now}, nil
}

func (b *TokenBucket) AllowAt(now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *TokenBucket) Wait(ctx context.Context) error {
	now := time.Now()
	b.mu.Lock()
	b.refill(now)
	delay := time.Duration(0)
	if b.tokens >= 1 {
		b.tokens--
	} else {
		deficit := 1 - b.tokens
		b.tokens--
		delay = time.Duration(deficit / b.rate * float64(time.Second))
	}
	b.mu.Unlock()
	if delay <= 0 {
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		b.mu.Lock()
		b.refill(time.Now())
		if b.tokens < b.capacity {
			b.tokens++
		}
		b.mu.Unlock()
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (b *TokenBucket) refill(now time.Time) {
	if now.Before(b.last) {
		return
	}
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
}
