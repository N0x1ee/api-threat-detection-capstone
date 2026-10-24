// Aggregation, verdict bands and adaptive weights. A direct port of app/decision.py
// (SRS v1.1 Sections 4.5, 5.7, 5.8); tests in engine_test.go mirror tests/test_decision.py.
package main

import (
	"fmt"
	"math"
	"sync"
	"time"
)

var AgentNames = []string{"anomaly", "payload", "behavior"}

type AgentResult struct {
	RequestID  string                 `json:"request_id"`
	Agent      string                 `json:"agent"`
	Score      *float64               `json:"score"`
	Confidence *float64               `json:"confidence"`
	Detail     map[string]interface{} `json:"detail"`
	LatencyMs  float64                `json:"latency_ms"`
	Model      string                 `json:"model"`
	Error      *string                `json:"error"`
}

func (r AgentResult) Valid() bool {
	return r.Error == nil && r.Score != nil && r.Confidence != nil
}

type Aggregation struct {
	Score         *float64           `json:"score"` // nil = insufficient evidence (AI-040)
	Mode          string             `json:"mode"`
	Numerator     float64            `json:"numerator"`
	Denominator   float64            `json:"denominator"`
	Contributions map[string]float64 `json:"contributions"`
	Participants  []string           `json:"participants"`
}

func orderedNames(results map[string]AgentResult) []string {
	var names []string
	seen := map[string]bool{}
	for _, n := range AgentNames {
		if _, ok := results[n]; ok {
			names = append(names, n)
			seen[n] = true
		}
	}
	for n := range results {
		if !seen[n] {
			names = append(names, n)
		}
	}
	return names
}

func weightOf(w map[string]float64, n string) float64 {
	if v, ok := w[n]; ok {
		return v
	}
	return 1.0
}

// Aggregate: mode A T = Σ(w·c·s)/Σ(w·c); B mean(s); C share of agents with s > voteThreshold.
func Aggregate(results map[string]AgentResult, weights map[string]float64, mode string,
	voteThreshold, epsilon float64) (Aggregation, error) {
	names := orderedNames(results)
	agg := Aggregation{Mode: mode, Contributions: map[string]float64{}, Participants: names}
	if len(names) == 0 {
		return agg, nil
	}
	n := float64(len(names))
	switch mode {
	case "A":
		for _, k := range names {
			r := results[k]
			t := weightOf(weights, k) * *r.Confidence * *r.Score
			agg.Contributions[k] = t
			agg.Numerator += t
			agg.Denominator += weightOf(weights, k) * *r.Confidence
		}
		if agg.Denominator >= epsilon {
			s := agg.Numerator / agg.Denominator
			agg.Score = &s
		}
	case "B":
		for _, k := range names {
			agg.Contributions[k] = *results[k].Score / n
			agg.Numerator += *results[k].Score
		}
		agg.Denominator = n
		s := agg.Numerator / n
		agg.Score = &s
	case "D": // confidence-weighted noisy-OR: agents can only raise the threat
		rest := 1.0
		for _, k := range names {
			r := results[k]
			t := math.Min(1, weightOf(weights, k)**r.Confidence**r.Score)
			agg.Contributions[k] = t
			rest *= 1 - t
		}
		agg.Numerator, agg.Denominator = 1-rest, 1
		s := 1 - rest
		agg.Score = &s
	case "C":
		for _, k := range names {
			if *results[k].Score > voteThreshold {
				agg.Contributions[k] = 1.0 / n
				agg.Numerator++
			} else {
				agg.Contributions[k] = 0
			}
		}
		agg.Denominator = n
		s := agg.Numerator / n
		agg.Score = &s
	default:
		return agg, fmt.Errorf("unknown aggregation mode %q", mode)
	}
	if agg.Score != nil {
		s := *agg.Score
		if s < -1e-9 || s > 1+1e-9 {
			return agg, fmt.Errorf("final score %v outside [0, 1]", s) // AI-039
		}
		s = math.Min(1, math.Max(0, s))
		agg.Score = &s
	}
	return agg, nil
}

// VerdictFor uses half-open bands (FR-042): ALLOW [0, t1), FLAG [t1, t2], BLOCK (t2, 1].
func VerdictFor(score, allowBelow, blockAbove float64) string {
	if score < allowBelow {
		return "ALLOW"
	}
	if score <= blockAbove {
		return "FLAG"
	}
	return "BLOCK"
}

// ------------------------------------------------------------------ adaptive weights

func MCC(tp, fp, fn, tn float64) float64 {
	den := math.Sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
	if den == 0 {
		return 0
	}
	return (tp*tn - fp*fn) / den
}

type WeightsCfg struct {
	Initial          float64 `json:"initial"`
	Min              float64 `json:"min"`
	Max              float64 `json:"max"`
	Alpha            float64 `json:"alpha"`
	MaxDelta         float64 `json:"max_delta"`
	UpdateEvery      int     `json:"update_every"`
	Window           int     `json:"window"`
	MinPositives     int     `json:"min_positives"`
	UseAnalystLabels bool    `json:"use_analyst_labels"`
	Frozen           bool    `json:"frozen"`
}

type labelled struct {
	y     int
	preds map[string]bool
	prov  string
}

type WeightUpdate struct {
	Ts         float64            `json:"ts"`
	Old        map[string]float64 `json:"old"`
	New        map[string]float64 `json:"new"`
	Window     int                `json:"window"`
	Positives  int                `json:"positives"`
	Provenance map[string]int     `json:"provenance"`
	Skipped    bool               `json:"skipped"`
	Reason     string             `json:"reason,omitempty"`
	MCC        map[string]float64 `json:"mcc,omitempty"`
}

// WeightManager: every UpdateEvery labels, perf_i = (MCC_i+1)/2 over the last Window labels,
// target_i = perf_i/mean(perf), w_i <- clip((1-α)w_i + α·target_i, min, max), |Δ| ≤ MaxDelta.
// Skipped (and logged) when the window holds fewer than MinPositives attacks.
type WeightManager struct {
	mu          sync.Mutex
	Cfg         WeightsCfg
	Weights     map[string]float64
	window      []labelled
	Seen        int
	sinceUpdate int
	Updates     int
	Skipped     int
	OnUpdate    func(WeightUpdate)
}

func NewWeightManager(cfg WeightsCfg) *WeightManager {
	wm := &WeightManager{Cfg: cfg}
	wm.Reset(nil)
	return wm
}

func (wm *WeightManager) Reset(w map[string]float64) {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	wm.Weights = map[string]float64{}
	for _, n := range AgentNames {
		wm.Weights[n] = wm.Cfg.Initial
		if v, ok := w[n]; ok {
			wm.Weights[n] = math.Min(wm.Cfg.Max, math.Max(wm.Cfg.Min, v))
		}
	}
	wm.window, wm.Seen, wm.sinceUpdate, wm.Updates, wm.Skipped = nil, 0, 0, 0, 0
}

func (wm *WeightManager) Snapshot() map[string]float64 {
	wm.mu.Lock()
	defer wm.mu.Unlock()
	out := map[string]float64{}
	for k, v := range wm.Weights {
		out[k] = v
	}
	return out
}

// Feedback records one labelled outcome. Returns the update entry when an update ran.
func (wm *WeightManager) Feedback(scores map[string]float64, label int, provenance string) *WeightUpdate {
	if provenance == "analyst" && !wm.Cfg.UseAnalystLabels {
		return nil
	}
	wm.mu.Lock()
	preds := map[string]bool{}
	for _, n := range AgentNames {
		if s, ok := scores[n]; ok {
			preds[n] = s >= 0.5
		}
	}
	y := 0
	if label != 0 {
		y = 1
	}
	wm.window = append(wm.window, labelled{y, preds, provenance})
	if len(wm.window) > wm.Cfg.Window {
		wm.window = wm.window[len(wm.window)-wm.Cfg.Window:]
	}
	wm.Seen++
	wm.sinceUpdate++
	if wm.sinceUpdate < wm.Cfg.UpdateEvery || wm.Cfg.Frozen {
		wm.mu.Unlock()
		return nil
	}
	wm.sinceUpdate = 0
	e := wm.update()
	cb := wm.OnUpdate
	wm.mu.Unlock()
	if cb != nil {
		cb(*e)
	}
	return e
}

func (wm *WeightManager) confusion(name string) (tp, fp, fn, tn float64) {
	for _, l := range wm.window {
		p, ok := l.preds[name]
		if !ok {
			continue
		}
		switch {
		case p && l.y == 1:
			tp++
		case p && l.y == 0:
			fp++
		case !p && l.y == 1:
			fn++
		default:
			tn++
		}
	}
	return
}

func copyW(w map[string]float64) map[string]float64 {
	o := map[string]float64{}
	for k, v := range w {
		o[k] = v
	}
	return o
}

func (wm *WeightManager) update() *WeightUpdate {
	pos := 0
	prov := map[string]int{"corpus": 0, "analyst": 0}
	for _, l := range wm.window {
		pos += l.y
		prov[l.prov]++
	}
	e := &WeightUpdate{Ts: float64(time.Now().UnixNano()) / 1e9, Old: copyW(wm.Weights),
		Window: len(wm.window), Positives: pos, Provenance: prov}
	if pos < wm.Cfg.MinPositives {
		wm.Skipped++
		e.Skipped = true
		e.Reason = fmt.Sprintf("only %d attacks in window (< %d)", pos, wm.Cfg.MinPositives)
		e.New = copyW(wm.Weights)
		return e
	}
	m, perf := map[string]float64{}, map[string]float64{}
	mean := 0.0
	for _, n := range AgentNames {
		m[n] = MCC(wm.confusion(n))
		perf[n] = (m[n] + 1) / 2
		mean += perf[n] / float64(len(AgentNames))
	}
	c := wm.Cfg
	nw := map[string]float64{}
	for _, n := range AgentNames {
		target := 1.0
		if mean > 0 {
			target = perf[n] / mean
		}
		w := (1-c.Alpha)*wm.Weights[n] + c.Alpha*target
		w = math.Max(wm.Weights[n]-c.MaxDelta, math.Min(wm.Weights[n]+c.MaxDelta, w))
		nw[n] = math.Max(c.Min, math.Min(c.Max, w))
	}
	wm.Weights = nw
	wm.Updates++
	e.MCC, e.New = m, copyW(nw)
	return e
}
