package testrun

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/dnstrike/dnstrike/internal/security"
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
	target, err := s.targets.GetTarget(ctx, input.TargetID)
	if err != nil {
		return models.Test{}, err
	}
	input.Scenario = strings.TrimSpace(input.Scenario)
	metadata, ok := s.scenarios.Get(input.Scenario)
	if !ok {
		return models.Test{}, errors.New("unsupported test scenario")
	}
	if !supportsEnabledProtocol(metadata, target) {
		return models.Test{}, errors.New("target does not enable a protocol supported by this scenario")
	}
	config, err := normalizeConfig(input.Config, metadata)
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

func normalizeConfig(raw json.RawMessage, metadata models.ScenarioMetadata) (json.RawMessage, error) {
	value := cloneConfig(metadata.DefaultConfig)
	if len(raw) > 0 {
		var supplied map[string]any
		if err := json.Unmarshal(raw, &supplied); err != nil {
			return nil, errors.New("test config must be a valid JSON object")
		}
		if supplied == nil {
			return nil, errors.New("test config must be a JSON object")
		}
		for key, item := range supplied {
			value[key] = item
		}
	}
	if err := validateScenarioConfig(value, metadata); err != nil {
		return nil, err
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, errors.New("failed to process test config")
	}
	return normalized, nil
}

func cloneConfig(source map[string]any) map[string]any {
	result := make(map[string]any, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func supportsEnabledProtocol(metadata models.ScenarioMetadata, target models.Target) bool {
	if len(metadata.SupportedProtocols) == 0 {
		return true
	}
	for _, protocol := range metadata.SupportedProtocols {
		if (protocol == "udp" && target.UDPEnabled) || (protocol == "tcp" && target.TCPEnabled) {
			return true
		}
	}
	return false
}

func validateScenarioConfig(config map[string]any, metadata models.ScenarioMetadata) error {
	limits := metadata.RecommendedLimits
	numericLimits := map[string]int{
		"qps": limits.MaxQPS, "start_qps": limits.MaxQPS, "step_qps": limits.MaxQPS,
		"max_qps": limits.MaxQPS, "max_burst_qps": limits.MaxQPS,
		"duration": limits.MaxDuration, "step_duration": limits.MaxDuration,
		"hold_duration": limits.MaxDuration, "workers": limits.MaxWorkers,
		"connections": limits.MaxWorkers,
	}
	for key, maximum := range numericLimits {
		if raw, exists := config[key]; exists {
			value, ok := positiveInteger(raw)
			if !ok {
				return fmt.Errorf("%s must be a positive integer", key)
			}
			if maximum > 0 && value > maximum {
				return fmt.Errorf("%s must not exceed %d", key, maximum)
			}
		}
	}
	if start, ok := configInteger(config, "start_qps"); ok {
		if maximum, maxOK := configInteger(config, "max_qps"); maxOK && start > maximum {
			return errors.New("start_qps must not exceed max_qps")
		}
	}
	if start, startOK := configInteger(config, "start_qps"); startOK {
		step, stepOK := configInteger(config, "step_qps")
		maximum, maxOK := configInteger(config, "max_qps")
		stepDuration, durationOK := configInteger(config, "step_duration")
		if stepOK && maxOK && durationOK {
			steps := ((maximum - start) / step) + 1
			if steps*stepDuration > limits.MaxDuration {
				return fmt.Errorf("QPS ramp total duration must not exceed %d seconds", limits.MaxDuration)
			}
		}
	}
	for _, key := range []string{"domain", "base_domain"} {
		if raw, exists := config[key]; exists {
			value, ok := raw.(string)
			value = strings.TrimSpace(value)
			if !ok || value == "" {
				return fmt.Errorf("%s must be a non-empty domain name", key)
			}
			if _, valid := dns.IsDomainName(dns.Fqdn(value)); !valid {
				return fmt.Errorf("%s is not a valid domain name", key)
			}
			config[key] = strings.TrimSuffix(value, ".")
		}
	}
	if raw, exists := config["domain_list"]; exists {
		values, ok := stringSlice(raw)
		if !ok {
			return errors.New("domain_list must be an array of domain names")
		}
		if len(values) == 0 || len(values) > 1000 {
			return errors.New("domain_list must contain between 1 and 1000 domain names")
		}
		for _, domain := range values {
			if _, valid := dns.IsDomainName(dns.Fqdn(strings.TrimSpace(domain))); !valid {
				return fmt.Errorf("domain_list contains an invalid domain name: %s", domain)
			}
		}
	}
	if raw, exists := config["subdomains"]; exists {
		values, ok := stringSlice(raw)
		if !ok || len(values) == 0 || len(values) > 100 {
			return errors.New("subdomains must contain between 1 and 100 labels")
		}
		for _, value := range values {
			label := strings.TrimSpace(value)
			if label == "" || strings.Contains(label, ".") || len(label) > 63 {
				return fmt.Errorf("subdomains contains an invalid label: %s", value)
			}
			if _, valid := dns.IsDomainName(dns.Fqdn(label + ".example")); !valid {
				return fmt.Errorf("subdomains contains an invalid label: %s", value)
			}
		}
	}
	if raw, exists := config["query_type"]; exists {
		value, ok := raw.(string)
		allowed := map[string]bool{"A": true, "AAAA": true, "MX": true, "TXT": true, "NS": true, "PTR": true, "SRV": true, "CNAME": true, "DNSKEY": true, "DS": true, "ANY": true, "SOA": true}
		value = strings.ToUpper(strings.TrimSpace(value))
		if !ok || !allowed[value] {
			return errors.New("query_type is not supported")
		}
		config["query_type"] = value
	}
	if raw, exists := config["payload_bytes"]; exists {
		value, ok := positiveInteger(raw)
		if !ok || value > 4096 {
			return errors.New("payload_bytes must be between 1 and 4096")
		}
	}
	if raw, exists := config["source_ip_pool"]; exists {
		pool, ok := raw.(string)
		if !ok {
			return errors.New("source_ip_pool must be a comma-separated string")
		}
		if err := validateSourceIPPool(pool); err != nil {
			return err
		}
	}
	return nil
}

func positiveInteger(raw any) (int, bool) {
	switch value := raw.(type) {
	case int:
		return value, value > 0
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 1 || value != math.Trunc(value) || value > float64(math.MaxInt) {
			return 0, false
		}
		return int(value), true
	default:
		return 0, false
	}
}

func stringSlice(raw any) ([]string, bool) {
	switch values := raw.(type) {
	case []string:
		return values, true
	case []any:
		result := make([]string, 0, len(values))
		for _, item := range values {
			value, ok := item.(string)
			if !ok {
				return nil, false
			}
			result = append(result, value)
		}
		return result, true
	default:
		return nil, false
	}
}

func configInteger(config map[string]any, key string) (int, bool) {
	raw, exists := config[key]
	if !exists {
		return 0, false
	}
	return positiveInteger(raw)
}

func validateSourceIPPool(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	items := strings.Split(value, ",")
	if len(items) > 256 {
		return errors.New("source_ip_pool must not contain more than 256 addresses")
	}
	for _, item := range items {
		ip := strings.TrimSpace(item)
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("source_ip_pool contains an invalid IP address: %s", ip)
		}
		if err := security.ValidatePrivateIP(ip); err != nil {
			return fmt.Errorf("source_ip_pool address %s is not private or local", ip)
		}
	}
	return nil
}
