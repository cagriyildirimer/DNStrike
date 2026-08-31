package limiter

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestTokenBucketBurstAndRefill(t *testing.T) {
	bucket, err := NewTokenBucket(10, 2)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(time.Second)
	if !bucket.AllowAt(now) || !bucket.AllowAt(now) {
		t.Fatal("initial burst was not available")
	}
	if bucket.AllowAt(now) {
		t.Fatal("bucket exceeded burst capacity")
	}
	if !bucket.AllowAt(now.Add(100 * time.Millisecond)) {
		t.Fatal("bucket did not refill at configured rate")
	}
}

func TestTokenBucketWaitHonorsCancellation(t *testing.T) {
	bucket, err := NewTokenBucket(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bucket.AllowAt(time.Now()) {
		t.Fatal("expected initial token")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	err = bucket.Wait(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if time.Since(started) > 100*time.Millisecond {
		t.Fatal("cancellation was not immediate")
	}
}

func TestTokenBucketRejectsUnsafeLimits(t *testing.T) {
	for _, config := range [][2]int{{0, 1}, {10001, 1}, {10, 0}, {10, 11}} {
		if _, err := NewTokenBucket(config[0], config[1]); err == nil {
			t.Fatalf("expected rejection for qps=%d burst=%d", config[0], config[1])
		}
	}
}
