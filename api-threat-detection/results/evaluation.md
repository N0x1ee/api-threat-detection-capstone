# Evaluation results

Seed 99 · 5427 requests (1600 malicious) · thresholds allow < 0.3, block > 0.7 · mode A · 2026-10-23 22:15:39

> These agents are still the prototype models, trained and tested on the synthetic generator. The numbers check that the pipeline and evaluation work; they are not research results yet.

## 1. Methods compared (every request analysed by the agents)

PR-AUC uses the raw score. The other columns use the live thresholds: **FLAG or BLOCK** = score ≥ 0.3, **BLOCK only** = score > 0.7.

| Method | PR-AUC | Precision (F/B) | Recall (F/B) | F1 (F/B) | False-alarm (F/B) | Recall (BLOCK) | False-alarm (BLOCK) |
|---|---|---|---|---|---|---|---|
| Mode A: confidence-weighted (ours) | 0.999 | 0.985 | 0.994 | 0.989 | 0.006 | 0.811 | 0.000 |
| Mode B: equal-weight average | 0.999 | 0.988 | 0.994 | 0.991 | 0.005 | 0.151 | 0.000 |
| Mode C: simple majority vote | 0.966 | 0.927 | 0.995 | 0.960 | 0.033 | 0.119 | 0.000 |
| Anomaly agent alone | 0.797 | 0.729 | 0.566 | 0.638 | 0.088 | 0.188 | 0.004 |
| Payload agent alone | 0.577 | 1.000 | 0.396 | 0.568 | 0.000 | 0.355 | 0.000 |
| Behavior agent alone | 0.965 | 0.956 | 0.902 | 0.928 | 0.018 | 0.804 | 0.005 |
| Mode A without anomaly agent | 0.999 | 0.981 | 0.994 | 0.988 | 0.008 | 0.871 | 0.000 |
| Mode A without payload agent | 0.967 | 0.957 | 0.902 | 0.929 | 0.017 | 0.793 | 0.003 |
| Mode A without behavior agent | 0.638 | 0.998 | 0.394 | 0.565 | 0.000 | 0.354 | 0.000 |

## 2. Adaptive weights (RQ-7)

Weights learned from the first 1628 requests (15 update(s), 1 skipped), then both versions scored on the remaining 3799.

Final weights: anomaly 0.93, payload 0.93, behavior 1.13

| Version | PR-AUC | Recall (F/B) | False-alarm (F/B) |
|---|---|---|---|
| Mode A, equal weights | 1.000 | 0.995 | 0.005 |
| Mode A, adapted weights | 0.999 | 0.993 | 0.006 |

## 3. Detection rate by group (score ≥ 0.3)

| Method | Known attacks | Novel (held out) | Scanner | Normal (false alarms) |
|---|---|---|---|---|
| Mode A: confidence-weighted (ours) | 1.000 | 0.969 | 1.000 | 0.006 |
| Mode B: equal-weight average | 1.000 | 0.972 | 1.000 | 0.005 |
| Mode C: simple majority vote | 1.000 | 0.975 | 1.000 | 0.033 |
| Anomaly agent alone | 0.653 | 0.656 | 0.507 | 0.088 |
| Payload agent alone | 1.000 | 0.981 | 0.000 | 0.000 |
| Behavior agent alone | 0.738 | 0.775 | 1.000 | 0.018 |
| Mode A without anomaly agent | 1.000 | 0.969 | 1.000 | 0.008 |
| Mode A without payload agent | 0.738 | 0.772 | 1.000 | 0.017 |
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

**Behavior agent** (ECE 0.250)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 0 | – | – |
| 0.2-0.4 | 0 | – | – |
| 0.4-0.6 | 2210 | 0.473 | 0.960 |
| 0.6-0.8 | 926 | 0.700 | 0.925 |
| 0.8-1.0 | 2291 | 0.932 | 0.963 |

## 5. Full live pipeline (fast filter + agents + thresholds)

| | ALLOW | FLAG | BLOCK |
|---|---|---|---|
| Normal requests | 1.000 | 0.000 | 0.000 |
| Malicious requests | 0.018 | 0.177 | 0.805 |

- Normal traffic cleared by the fast filter: **98.7%** (an observation, not a target)
- Attacks the fast filter wrongly cleared: **1.2%**
- Decisions made in degraded mode (an agent timed out or failed): **0**
- Analysis path: p50 2.1 ms, p95 4.3 ms, p99 5.5 ms (target p95 ≤ 200 ms)
- Bypass path: p50 0.03 ms, p95 0.09 ms, p99 0.13 ms (target p95 ≤ 20 ms)

Per-stage latency (ms; fast filter over all requests, other stages over analysed requests):

| Stage | p50 | p95 | p99 |
|---|---|---|---|
| fast filter | 0.028 | 0.072 | 0.096 |
| agents | 1.931 | 4.183 | 5.424 |
| aggregation | 0.012 | 0.016 | 0.034 |
| explanation | 0.026 | 0.041 | 0.063 |

Latency here is in-process (no network) on the machine that ran this script.

Model file md5: `e7b318e11cf3d10d7837f8927a984b27` · Python 3.13.16. Full config in `evaluation.json`.
