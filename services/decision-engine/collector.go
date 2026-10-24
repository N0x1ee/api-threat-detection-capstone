// Collects agent results per request and finalises a decision when every enabled agent has
// answered or the deadline passes (FR-033, FR-034, FR-036).
package main

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

type Decision struct {
	RequestID     string                            `json:"request_id"`
	Ts            float64                           `json:"ts"`
	Route         string                            `json:"route"`
	Verdict       string                            `json:"verdict"`
	Score         *float64                          `json:"score"`
	Mode          string                            `json:"mode"`
	Thresholds    map[string]float64                `json:"thresholds"`
	Agents        map[string]map[string]interface{} `json:"agents"`
	Excluded      map[string]string                 `json:"excluded"`
	Degraded      bool                              `json:"degraded"`
	PolicyUsed    *string                           `json:"policy_used"`
	Numerator     float64                           `json:"numerator"`
	Denominator   float64                           `json:"denominator"`
	Contributions map[string]float64                `json:"contributions"`
	Request       json.RawMessage                   `json:"request"`
	TimingsMs     map[string]float64                `json:"timings_ms"`
}

type pending struct {
	request  json.RawMessage
	started  time.Time
	deadline time.Time
	results  map[string]AgentResult
}

type Collector struct {
	mu      sync.Mutex
	cfg     *Config
	weights *WeightManager
	items   map[string]*pending
	emit    func(Decision)
	now     func() time.Time
}

func NewCollector(cfg *Config, wm *WeightManager, emit func(Decision)) *Collector {
	return &Collector{cfg: cfg, weights: wm, items: map[string]*pending{}, emit: emit, now: time.Now}
}

func (c *Collector) enabled() []string {
	var out []string
	for _, n := range AgentNames {
		if !c.cfg.Disabled(n) {
			out = append(out, n)
		}
	}
	return out
}

func (c *Collector) get(id string) *pending {
	p, ok := c.items[id]
	if !ok {
		t := c.now()
		p = &pending{started: t, deadline: t.Add(c.cfg.AgentTimeout()), results: map[string]AgentResult{}}
		c.items[id] = p
	}
	return p
}

// OnRequest is called for each message on requests.suspicious.
func (c *Collector) OnRequest(id string, raw json.RawMessage, deadlineMs float64) {
	c.mu.Lock()
	p := c.get(id)
	p.request = raw
	if deadlineMs > 0 {
		p.deadline = p.started.Add(time.Duration(deadlineMs * float64(time.Millisecond)))
	}
	done := c.complete(p)
	c.mu.Unlock()
	if done {
		c.finalise(id)
	}
}

// OnResult is called for each message on agent.results.
func (c *Collector) OnResult(r AgentResult) {
	if r.RequestID == "" || c.cfg.Disabled(r.Agent) {
		return
	}
	c.mu.Lock()
	p := c.get(r.RequestID)
	p.results[r.Agent] = r
	done := c.complete(p)
	c.mu.Unlock()
	if done {
		c.finalise(r.RequestID)
	}
}

func (c *Collector) complete(p *pending) bool {
	if p.request == nil {
		return false
	}
	for _, n := range c.enabled() {
		if _, ok := p.results[n]; !ok {
			return false
		}
	}
	return true
}

// Sweep finalises every request past its deadline. Called by a ticker.
func (c *Collector) Sweep() {
	t := c.now()
	var due []string
	c.mu.Lock()
	for id, p := range c.items {
		if t.After(p.deadline) {
			due = append(due, id)
		}
		// results for a request we never saw: drop after a grace period
		if p.request == nil && t.Sub(p.started) > 10*c.cfg.AgentTimeout() {
			delete(c.items, id)
		}
	}
	c.mu.Unlock()
	sort.Strings(due)
	for _, id := range due {
		c.finalise(id)
	}
}

func (c *Collector) Pending() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.items)
}

func (c *Collector) finalise(id string) {
	c.mu.Lock()
	p, ok := c.items[id]
	if !ok || p.request == nil {
		c.mu.Unlock()
		return
	}
	delete(c.items, id)
	c.mu.Unlock()

	elapsed := c.now().Sub(p.started)
	valid := map[string]AgentResult{}
	excluded := map[string]string{}
	for _, n := range c.enabled() {
		r, ok := p.results[n]
		switch {
		case !ok:
			excluded[n] = fmt.Sprintf("timed out after %d ms", c.cfg.AgentTimeout().Milliseconds())
		case !r.Valid():
			msg := "no score returned"
			if r.Error != nil {
				msg = *r.Error
			}
			excluded[n] = "error: " + msg
		default:
			valid[n] = r
		}
	}
	for _, n := range AgentNames {
		if c.cfg.Disabled(n) {
			excluded[n] = "disabled in configuration"
		}
	}
	w := c.weights.Snapshot()
	t0 := time.Now()
	agg, err := Aggregate(valid, w, c.cfg.Aggregation.Mode, c.cfg.Aggregation.VoteThreshold, c.cfg.Aggregation.Epsilon)
	aggMs := float64(time.Since(t0).Microseconds()) / 1000
	d := Decision{RequestID: id, Ts: float64(c.now().UnixNano()) / 1e9, Route: "ai", Mode: agg.Mode,
		Thresholds: map[string]float64{"allow_below": c.cfg.Thresholds.AllowBelow, "block_above": c.cfg.Thresholds.BlockAbove},
		Agents:     map[string]map[string]interface{}{}, Excluded: excluded, Request: p.request,
		Numerator: agg.Numerator, Denominator: agg.Denominator, Contributions: agg.Contributions,
		TimingsMs: map[string]float64{"agents": float64(elapsed.Microseconds()) / 1000, "aggregation": aggMs}}
	for n, r := range valid {
		d.Agents[n] = map[string]interface{}{"score": *r.Score, "confidence": *r.Confidence, "weight": weightOf(w, n),
			"detail": r.Detail, "latency_ms": r.LatencyMs, "model": r.Model}
	}
	d.Degraded = len(excluded) > 0
	if err != nil || agg.Score == nil {
		policy := c.cfg.Agents.FailurePolicy // FR-036
		d.PolicyUsed = &policy
		d.Verdict = "FLAG"
		if policy == "fail_closed" {
			d.Verdict = "BLOCK"
		}
	} else {
		d.Score = agg.Score
		d.Verdict = VerdictFor(*agg.Score, c.cfg.Thresholds.AllowBelow, c.cfg.Thresholds.BlockAbove)
	}
	c.emit(d)
}
