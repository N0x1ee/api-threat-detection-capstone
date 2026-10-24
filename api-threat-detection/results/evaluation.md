# Evaluation results

Seed 99 · 5427 requests (1600 malicious) · thresholds allow < 0.3, block > 0.7 · mode D · 2026-10-24 17:21:54

> These agents are still the prototype models, trained and tested on the synthetic generator. The numbers check that the pipeline and evaluation work; they are not research results yet.

## 1. Methods compared (every request analysed by the agents)

PR-AUC uses the raw score. The other columns use the live thresholds: **FLAG or BLOCK** = score ≥ 0.3, **BLOCK only** = score > 0.7.

| Method | PR-AUC | Precision (F/B) | Recall (F/B) | F1 (F/B) | False-alarm (F/B) | Recall (BLOCK) | False-alarm (BLOCK) |
|---|---|---|---|---|---|---|---|
| Mode A: confidence-weighted mean | 1.000 | 0.999 | 0.964 | 0.982 | 0.000 | 0.519 | 0.000 |
| Mode B: equal-weight average | 0.997 | 0.996 | 0.975 | 0.985 | 0.002 | 0.000 | 0.000 |
| Mode C: simple majority vote | 0.959 | 0.945 | 0.984 | 0.964 | 0.024 | 0.000 | 0.000 |
| Mode D: confidence-weighted noisy-OR (default) | 1.000 | 1.000 | 0.935 | 0.966 | 0.000 | 0.834 | 0.000 |
| Anomaly agent alone | 0.797 | 0.729 | 0.566 | 0.638 | 0.088 | 0.188 | 0.004 |
| Payload agent alone | 0.577 | 1.000 | 0.396 | 0.568 | 0.000 | 0.355 | 0.000 |
| Behavior agent alone | 0.761 | 0.820 | 0.601 | 0.693 | 0.055 | 0.599 | 0.002 |
| Mode A without anomaly agent | 1.000 | 0.998 | 0.962 | 0.980 | 0.001 | 0.573 | 0.000 |
| Mode A without payload agent | 0.771 | 0.961 | 0.601 | 0.739 | 0.010 | 0.596 | 0.000 |
| Mode A without behavior agent | 0.638 | 0.998 | 0.394 | 0.565 | 0.000 | 0.354 | 0.000 |

## 2. Adaptive weights (RQ-7)

Weights learned from the first 1628 requests (15 update(s), 1 skipped), then both versions scored on the remaining 3799.

Final weights: anomaly 0.97, payload 0.97, behavior 1.07

| Version | PR-AUC | Recall (F/B) | False-alarm (F/B) |
|---|---|---|---|
| Mode A, equal weights | 1.000 | 0.963 | 0.000 |
| Mode A, adapted weights | 1.000 | 0.961 | 0.000 |

## 3. Detection rate by group (score ≥ 0.3)

| Method | Known attacks | Novel (held out) | Scanner | Normal (false alarms) |
|---|---|---|---|---|
| Mode A: confidence-weighted mean | 1.000 | 0.825 | 0.999 | 0.000 |
| Mode B: equal-weight average | 1.000 | 0.878 | 0.999 | 0.002 |
| Mode C: simple majority vote | 1.000 | 0.925 | 0.999 | 0.024 |
| Mode D: confidence-weighted noisy-OR (default) | 1.000 | 0.863 | 0.938 | 0.000 |
| Anomaly agent alone | 0.653 | 0.656 | 0.507 | 0.088 |
| Payload agent alone | 1.000 | 0.981 | 0.000 | 0.000 |
| Behavior agent alone | 0.003 | 0.003 | 0.999 | 0.055 |
| Mode A without anomaly agent | 1.000 | 0.812 | 0.999 | 0.001 |
| Mode A without payload agent | 0.003 | 0.003 | 0.999 | 0.010 |
| Mode A without behavior agent | 1.000 | 0.972 | 0.000 | 0.000 |

## 4. Confidence calibration

For each agent: requests grouped by the agent's confidence, and how often its own call (score ≥ 0.5) was right. A well-calibrated agent has accuracy close to its confidence. ECE = expected calibration error (lower is better).

**Anomaly agent** (ECE 0.668)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 3480 | 0.076 | 0.724 |
| 0.2-0.4 | 1764 | 0.277 | 0.994 |
| 0.4-0.6 | 183 | 0.435 | 1.000 |
| 0.6-0.8 | 0 | – | – |
| 0.8-1.0 | 0 | – | – |

**Payload agent** (ECE 0.157)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 0 | – | – |
| 0.2-0.4 | 2190 | 0.300 | 0.562 |
| 0.4-0.6 | 123 | 0.530 | 0.805 |
| 0.6-0.8 | 524 | 0.738 | 0.964 |
| 0.8-1.0 | 2590 | 0.952 | 1.000 |

**Behavior agent** (ECE 0.313)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 1195 | 0.186 | 0.994 |
| 0.2-0.4 | 1194 | 0.399 | 0.826 |
| 0.4-0.6 | 985 | 0.600 | 0.768 |
| 0.6-0.8 | 726 | 0.800 | 0.723 |
| 0.8-1.0 | 1327 | 1.000 | 0.998 |

## 5. Full live pipeline (fast filter + agents + thresholds)

| | ALLOW | FLAG | BLOCK |
|---|---|---|---|
| Normal requests | 1.000 | 0.000 | 0.000 |
| Malicious requests | 0.077 | 0.092 | 0.830 |

- Normal traffic cleared by the fast filter: **98.7%** (an observation, not a target)
- Attacks the fast filter wrongly cleared: **1.2%**
- Decisions made in degraded mode (an agent timed out or failed): **0**
- Analysis path: p50 2.2 ms, p95 3.5 ms, p99 4.9 ms (target p95 ≤ 200 ms)
- Bypass path: p50 0.03 ms, p95 0.09 ms, p99 0.13 ms (target p95 ≤ 20 ms)

Per-stage latency (ms; fast filter over all requests, other stages over analysed requests):

| Stage | p50 | p95 | p99 |
|---|---|---|---|
| fast filter | 0.024 | 0.067 | 0.093 |
| agents | 2.098 | 3.313 | 4.788 |
| aggregation | 0.008 | 0.011 | 0.026 |
| explanation | 0.021 | 0.058 | 0.092 |

Latency here is in-process (no network) on the machine that ran this script.

Model file md5: `e7b318e11cf3d10d7837f8927a984b27` · Python 3.13.16. Full config in `evaluation.json`.
