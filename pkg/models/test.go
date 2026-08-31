package models

import (
	"encoding/json"
	"time"
)

type TestStatus string

const (
	TestPending   TestStatus = "PENDING"
	TestRunning   TestStatus = "RUNNING"
	TestCompleted TestStatus = "COMPLETED"
	TestFailed    TestStatus = "FAILED"
	TestCancelled TestStatus = "CANCELLED"
)

func (s TestStatus) Valid() bool {
	switch s {
	case TestPending, TestRunning, TestCompleted, TestFailed, TestCancelled:
		return true
	default:
		return false
	}
}

func (s TestStatus) Terminal() bool {
	return s == TestCompleted || s == TestFailed || s == TestCancelled
}

func (s TestStatus) CanTransition(next TestStatus) bool {
	switch s {
	case TestPending:
		return next == TestRunning || next == TestFailed || next == TestCancelled
	case TestRunning:
		return next == TestCompleted || next == TestFailed || next == TestCancelled
	default:
		return false
	}
}

type Test struct {
	ID              int64           `json:"id"`
	TargetID        int64           `json:"target_id"`
	Scenario        string          `json:"scenario"`
	Status          TestStatus      `json:"status"`
	CreatedAt       time.Time       `json:"created_at"`
	StartedAt       *time.Time      `json:"started_at,omitempty"`
	FinishedAt      *time.Time      `json:"finished_at,omitempty"`
	DurationSeconds int             `json:"duration_seconds"`
	Config          json.RawMessage `json:"config"`
	ResilienceScore *float64        `json:"resilience_score,omitempty"`
}

type CreateTestInput struct {
	TargetID int64           `json:"target_id"`
	Scenario string          `json:"scenario"`
	Config   json.RawMessage `json:"config"`
}

type TestFilter struct {
	TargetID int64
	Scenario string
	Status   TestStatus
	Limit    int
}
