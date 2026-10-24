package main

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// Config reads the same config.json as the Python services (api-threat-detection/config.json).
type Config struct {
	Thresholds struct {
		AllowBelow float64 `json:"allow_below"`
		BlockAbove float64 `json:"block_above"`
	} `json:"thresholds"`
	Aggregation struct {
		Mode          string  `json:"mode"`
		VoteThreshold float64 `json:"vote_threshold"`
		Epsilon       float64 `json:"epsilon"`
	} `json:"aggregation"`
	Weights WeightsCfg `json:"weights"`
	Agents  struct {
		TimeoutMs     float64  `json:"timeout_ms"`
		DisabledList  []string `json:"disabled"`
		FailurePolicy string   `json:"failure_policy"`
	} `json:"agents"`
}

func DefaultConfig() *Config {
	c := &Config{}
	c.Thresholds.AllowBelow, c.Thresholds.BlockAbove = 0.3, 0.7
	c.Aggregation.Mode, c.Aggregation.VoteThreshold, c.Aggregation.Epsilon = "A", 0.5, 1e-6
	c.Weights = WeightsCfg{Initial: 1, Min: 0.1, Max: 2, Alpha: 0.3, MaxDelta: 0.2, UpdateEvery: 1000,
		Window: 1000, MinPositives: 30, UseAnalystLabels: true}
	c.Agents.TimeoutMs, c.Agents.FailurePolicy = 150, "fail_open_flag"
	return c
}

func LoadConfig(path string) (*Config, error) {
	c := DefaultConfig()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if err := json.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("config: %w", err)
		}
	}
	return c, c.Validate()
}

func (c *Config) Validate() error {
	t := c.Thresholds
	if !(0 <= t.AllowBelow && t.AllowBelow < t.BlockAbove && t.BlockAbove <= 1) {
		return fmt.Errorf("thresholds: need 0 <= allow_below < block_above <= 1")
	}
	if m := c.Aggregation.Mode; m != "A" && m != "B" && m != "C" {
		return fmt.Errorf("aggregation.mode must be A, B or C")
	}
	if c.Weights.Min <= 0 || c.Weights.Min > c.Weights.Max {
		return fmt.Errorf("weights.min must be > 0 and <= weights.max")
	}
	if p := c.Agents.FailurePolicy; p != "fail_open_flag" && p != "fail_closed" {
		return fmt.Errorf("agents.failure_policy must be fail_open_flag or fail_closed")
	}
	if c.Agents.TimeoutMs <= 0 {
		return fmt.Errorf("agents.timeout_ms must be > 0")
	}
	return nil
}

func (c *Config) Disabled(agent string) bool {
	for _, d := range c.Agents.DisabledList {
		if d == agent {
			return true
		}
	}
	return false
}

func (c *Config) AgentTimeout() time.Duration {
	return time.Duration(c.Agents.TimeoutMs * float64(time.Millisecond))
}
