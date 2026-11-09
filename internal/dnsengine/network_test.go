package dnsengine

import (
	"errors"
	"testing"
)

func TestIPManagerRejectsAllocationWhenDisabled(t *testing.T) {
	manager := NewIPManager(false)
	if err := manager.Allocate("192.168.50.10"); !errors.Is(err, ErrSourceIPPoolDisabled) {
		t.Fatalf("expected disabled allocation error, got %v", err)
	}
}
