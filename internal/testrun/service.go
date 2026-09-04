package testrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dnstrike/dnstrike/pkg/models"
)

var ErrInvalidTransition = errors.New("invalid test status transition")

type Repository interface {
	CreateTest(context.Context, *models.Test) error
	ListTests(context.Context, models.TestFilter) ([]models.Test, error)
	GetTest(context.Context, int64) (models.Test, error)
	TransitionTest(context.Context, int64, models.TestStatus, models.TestStatus, time.Time) error
	UpdateTestResult(context.Context, int64, int, json.RawMessage) error
	DeleteTest(context.Context, int64) error
}

type TargetRepository interface {
	GetTarget(context.Context, int64) (models.Target, error)
}

type ScenarioRegistry interface {
	Get(string) (models.ScenarioMetadata, bool)
}

type Service struct {
	repo      Repository
	targets   TargetRepository
	scenarios ScenarioRegistry
}

func NewService(repo Repository, targets TargetRepository, scenarios ScenarioRegistry) *Service {
	return &Service{repo: repo, targets: targets, scenarios: scenarios}
}

func (s *Service) SaveResult(ctx context.Context, id int64, score int, result json.RawMessage) error {
	return s.repo.UpdateTestResult(ctx, id, score, result)
}

func (s *Service) Delete(ctx context.Context, id int64) error {
	return s.repo.DeleteTest(ctx, id)
}

func (s *Service) Create(ctx context.Context, input models.CreateTestInput) (models.Test, error) {
	if input.TargetID < 1 {
		return models.Test{}, errors.New("select a valid target")
	}
	if _, err := s.targets.GetTarget(ctx, input.TargetID); err != nil {
		return models.Test{}, err
	}
	input.Scenario = strings.TrimSpace(input.Scenario)
	if _, ok := s.scenarios.Get(input.Scenario); !ok {
		return models.Test{}, errors.New("unsupported test scenario")
	}
	config, err := normalizeConfig(input.Config)
	if err != nil {
		return models.Test{}, err
	}
	test := models.Test{TargetID: input.TargetID, Scenario: input.Scenario, Status: models.TestPending, Config: config}
	if err := s.repo.CreateTest(ctx, &test); err != nil {
		return models.Test{}, err
	}
	return test, nil
}

func (s *Service) List(ctx context.Context, filter models.TestFilter) ([]models.Test, error) {
	filter.Scenario = strings.TrimSpace(filter.Scenario)
	if filter.Status != "" && !filter.Status.Valid() {
		return nil, errors.New("invalid test status filter")
	}
	if filter.Limit < 0 || filter.Limit > 500 {
		return nil, errors.New("limit must be between 1 and 500")
	}
	return s.repo.ListTests(ctx, filter)
}

func (s *Service) Get(ctx context.Context, id int64) (models.Test, error) {
	return s.repo.GetTest(ctx, id)
}

func (s *Service) Transition(ctx context.Context, id int64, next models.TestStatus, at time.Time) (models.Test, error) {
	if !next.Valid() {
		return models.Test{}, fmt.Errorf("%w: unknown target status", ErrInvalidTransition)
	}
	current, err := s.repo.GetTest(ctx, id)
	if err != nil {
		return models.Test{}, err
	}
	if !current.Status.CanTransition(next) {
		return models.Test{}, fmt.Errorf("%w: %s → %s", ErrInvalidTransition, current.Status, next)
	}
	if err := s.repo.TransitionTest(ctx, id, current.Status, next, at); err != nil {
		return models.Test{}, err
	}
	return s.repo.GetTest(ctx, id)
}

func normalizeConfig(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage(`{}`), nil
	}
	var value map[string]any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, errors.New("test config must be a valid JSON object")
	}
	if value == nil {
		return nil, errors.New("test config must be a JSON object")
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("failed to process test config")
	}
	return normalized, nil
}
