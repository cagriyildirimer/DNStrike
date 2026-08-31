package models

type ScenarioMetadata struct {
	ID                 string         `json:"id"`
	Name               string         `json:"name"`
	Category           string         `json:"category"`
	Description        string         `json:"description"`
	SupportedProtocols []string       `json:"supported_protocols"`
	RequiredParameters []string       `json:"required_parameters"`
	RiskLevel          string         `json:"risk_level"`
	DefaultConfig      map[string]any `json:"default_config"`
	RecommendedLimits  Limits         `json:"recommended_limits"`
}

type Limits struct {
	MaxQPS      int `json:"max_qps"`
	MaxDuration int `json:"max_duration_seconds"`
	MaxWorkers  int `json:"max_workers"`
}
