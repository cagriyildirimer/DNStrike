package models

import "testing"

func TestTestStatusTransitions(t *testing.T) {
	t.Parallel()
	allowed := []struct{ from, to TestStatus }{
		{TestPending, TestRunning}, {TestPending, TestFailed}, {TestPending, TestCancelled},
		{TestRunning, TestCompleted}, {TestRunning, TestFailed}, {TestRunning, TestCancelled},
	}
	for _, transition := range allowed {
		if !transition.from.CanTransition(transition.to) {
			t.Errorf("expected %s -> %s to be allowed", transition.from, transition.to)
		}
	}
	for _, terminal := range []TestStatus{TestCompleted, TestFailed, TestCancelled} {
		if !terminal.Terminal() {
			t.Errorf("expected %s to be terminal", terminal)
		}
		if terminal.CanTransition(TestRunning) {
			t.Errorf("terminal status %s accepted a transition", terminal)
		}
	}
}
