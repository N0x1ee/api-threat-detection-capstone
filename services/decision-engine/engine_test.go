package main

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func f(v float64) *float64 { return &v }

func R(s, c float64) AgentResult { return AgentResult{Score: f(s), Confidence: f(c)} }

var equal = map[string]float64{"anomaly": 1, "payload": 1, "behavior": 1}

func near(t *testing.T, got, want float64) {
	t.Helper()
	if math.Abs(got-want) > 1e-9 {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestModeAFormula(t *testing.T) {
	res := map[string]AgentResult{"anomaly": R(0.2, 0.5), "payload": R(0.9, 1.0), "behavior": R(0.1, 0.25)}
	w := map[string]float64{"anomaly": 1, "payload": 2, "behavior": 0.5}
	a, _ := Aggregate(res, w, "A", 0.5, 1e-6)
	num := 1.0*0.5*0.2 + 2.0*1.0*0.9 + 0.5*0.25*0.1
	den := 1.0*0.5 + 2.0*1.0 + 0.5*0.25
	near(t, *a.Score, num/den)
	near(t, a.Numerator, num)
	near(t, a.Denominator, den)
}

func TestModesBC(t *testing.T) {
	res := map[string]AgentResult{"anomaly": R(0.2, 0.9), "payload": R(0.9, 0.9), "behavior": R(0.6, 0.9)}
	b, _ := Aggregate(res, equal, "B", 0.5, 1e-6)
	near(t, *b.Score, (0.2+0.9+0.6)/3)
	c, _ := Aggregate(res, equal, "C", 0.5, 1e-6)
	near(t, *c.Score, 2.0/3)
}

func TestInsufficientEvidenceAndEmpty(t *testing.T) {
	res := map[string]AgentResult{"anomaly": R(0.9, 0), "payload": R(0.9, 0), "behavior": R(0.9, 0)}
	if a, _ := Aggregate(res, equal, "A", 0.5, 1e-6); a.Score != nil {
		t.Fatal("expected nil score")
	}
	if a, _ := Aggregate(map[string]AgentResult{}, equal, "A", 0.5, 1e-6); a.Score != nil {
		t.Fatal("expected nil score")
	}
	if _, err := Aggregate(res, equal, "Z", 0.5, 1e-6); err == nil {
		t.Fatal("expected error for unknown mode")
	}
}

func TestBands(t *testing.T) {
	cases := map[float64]string{0.2999: "ALLOW", 0.3: "FLAG", 0.7: "FLAG", 0.7001: "BLOCK", 0: "ALLOW", 1: "BLOCK"}
	for s, want := range cases {
		if got := VerdictFor(s, 0.3, 0.7); got != want {
			t.Fatalf("%v: got %s want %s", s, got, want)
		}
	}
}

func cfgW() WeightsCfg {
	return WeightsCfg{Initial: 1, Min: 0.1, Max: 2, Alpha: 0.3, MaxDelta: 0.2, UpdateEvery: 50, Window: 200,
		MinPositives: 10, UseAnalystLabels: true}
}

func feed(wm *WeightManager, n int) {
	for i := 0; i < n; i++ {
		y := 0
		if i%2 == 0 {
			y = 1
		}
		p, a, b := 0.1, 0.9, 0.1
		if y == 1 {
			p, a = 0.9, 0.1
		}
		if i%3 == 0 {
			b = 0.9
		}
		wm.Feedback(map[string]float64{"payload": p, "anomaly": a, "behavior": b}, y, "corpus")
	}
}

func TestWeights(t *testing.T) {
	wm := NewWeightManager(cfgW())
	feed(wm, 49)
	if wm.Updates != 0 {
		t.Fatal("no update before N")
	}
	feed(wm, 1)
	if wm.Updates != 1 || wm.Weights["payload"] <= 1 || wm.Weights["anomaly"] >= 1 {
		t.Fatalf("bad first update %+v", wm.Weights)
	}
	feed(wm, 5000)
	for _, w := range wm.Weights {
		if w < 0.1 || w > 2 {
			t.Fatalf("out of bounds %v", w)
		}
	}
	if wm.Weights["anomaly"] >= wm.Weights["payload"] {
		t.Fatal("bad agent should lose weight")
	}
}

func TestWeightsSkipAndFrozenAndAnalyst(t *testing.T) {
	wm := NewWeightManager(cfgW())
	for i := 0; i < 50; i++ {
		wm.Feedback(map[string]float64{"payload": 0.1, "anomaly": 0.1, "behavior": 0.1}, 0, "corpus")
	}
	if wm.Updates != 0 || wm.Skipped != 1 {
		t.Fatal("expected skip")
	}
	c := cfgW()
	c.Frozen = true
	fz := NewWeightManager(c)
	feed(fz, 200)
	if fz.Updates != 0 {
		t.Fatal("frozen must not update")
	}
	c = cfgW()
	c.UseAnalystLabels = false
	na := NewWeightManager(c)
	if na.Feedback(map[string]float64{"payload": 0.9}, 1, "analyst"); na.Seen != 0 {
		t.Fatal("analyst labels should be ignored")
	}
}

// ---------------------------------------------------------------- collector

type clock struct{ t time.Time }

func newCollector(t *testing.T, mutate func(*Config)) (*Collector, *[]Decision, *clock) {
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	var out []Decision
	c := NewCollector(cfg, NewWeightManager(cfg.Weights), func(d Decision) { out = append(out, d) })
	ck := &clock{time.Unix(1000, 0)}
	c.now = func() time.Time { return ck.t }
	return c, &out, ck
}

func res(id, agent string, s, conf float64) AgentResult {
	r := R(s, conf)
	r.RequestID, r.Agent = id, agent
	return r
}

func TestCollectorAllAgents(t *testing.T) {
	c, out, _ := newCollector(t, nil)
	c.OnResult(res("r1", "payload", 0.95, 0.9)) // result before the request event
	c.OnRequest("r1", json.RawMessage(`{"request_id":"r1"}`), 0)
	c.OnResult(res("r1", "anomaly", 0.9, 0.9))
	if len(*out) != 0 {
		t.Fatal("decided too early")
	}
	c.OnResult(res("r1", "behavior", 0.9, 0.9))
	if len(*out) != 1 || (*out)[0].Verdict != "BLOCK" || (*out)[0].Degraded {
		t.Fatalf("got %+v", *out)
	}
	if c.Pending() != 0 {
		t.Fatal("pending not cleared")
	}
}

func TestCollectorTimeoutDegraded(t *testing.T) { // FR-033, FR-034
	c, out, ck := newCollector(t, nil)
	c.OnRequest("r2", json.RawMessage(`{}`), 0)
	c.OnResult(res("r2", "payload", 0.1, 0.9))
	ck.t = ck.t.Add(100 * time.Millisecond)
	c.Sweep()
	if len(*out) != 0 {
		t.Fatal("decided before deadline")
	}
	ck.t = ck.t.Add(60 * time.Millisecond)
	c.Sweep()
	d := (*out)[0]
	if !d.Degraded || d.Verdict != "ALLOW" || d.Excluded["anomaly"] == "" || d.Excluded["behavior"] == "" {
		t.Fatalf("got %+v", d)
	}
}

func TestCollectorAgentErrorAndFailOpen(t *testing.T) { // FR-036
	c, out, ck := newCollector(t, nil)
	c.OnRequest("r3", json.RawMessage(`{}`), 0)
	msg := "model not loaded"
	c.OnResult(AgentResult{RequestID: "r3", Agent: "payload", Error: &msg})
	ck.t = ck.t.Add(time.Second)
	c.Sweep()
	d := (*out)[0]
	if d.Verdict != "FLAG" || d.PolicyUsed == nil || *d.PolicyUsed != "fail_open_flag" || d.Score != nil {
		t.Fatalf("got %+v", d)
	}
	if d.Excluded["payload"] != "error: model not loaded" {
		t.Fatalf("got %q", d.Excluded["payload"])
	}
}

func TestCollectorFailClosedAndDisabled(t *testing.T) {
	c, out, _ := newCollector(t, func(cfg *Config) {
		cfg.Agents.FailurePolicy = "fail_closed"
		cfg.Agents.DisabledList = []string{"anomaly", "behavior"}
	})
	c.OnRequest("r4", json.RawMessage(`{}`), 0)
	c.OnResult(res("r4", "payload", 0.95, 0)) // zero confidence -> insufficient evidence
	d := (*out)[0]
	if d.Verdict != "BLOCK" || d.Excluded["anomaly"] != "disabled in configuration" {
		t.Fatalf("got %+v", d)
	}
}

func TestConfigValidation(t *testing.T) {
	c := DefaultConfig()
	c.Thresholds.AllowBelow, c.Thresholds.BlockAbove = 0.7, 0.3
	if c.Validate() == nil {
		t.Fatal("bad thresholds accepted")
	}
	if _, err := LoadConfig("../../api-threat-detection/config.json"); err != nil {
		t.Fatalf("repo config rejected: %v", err)
	}
}
