# Evaluation results

Seed 99 · 5427 requests (1600 malicious) · thresholds allow < 0.3, block > 0.7 · mode A · 2026-10-23 20:26:54

> These agents are still the prototype models, trained and tested on the synthetic generator. The numbers check that the pipeline and evaluation work; they are not research results yet.

## 1. Methods compared (every request analysed by the agents)

PR-AUC uses the raw score. The other columns use the live thresholds: **FLAG or BLOCK** = score ≥ 0.3, **BLOCK only** = score > 0.7.

| Method | PR-AUC | Precision (F/B) | Recall (F/B) | F1 (F/B) | False-alarm (F/B) | Recall (BLOCK) | False-alarm (BLOCK) |
|---|---|---|---|---|---|---|---|
| Mode A: confidence-weighted (ours) | 1.000 | 0.989 | 0.996 | 0.992 | 0.005 | 0.259 | 0.000 |
| Mode B: equal-weight average | 1.000 | 0.988 | 0.996 | 0.992 | 0.005 | 0.218 | 0.000 |
| Mode C: simple majority vote | 0.951 | 0.928 | 0.996 | 0.961 | 0.032 | 0.171 | 0.000 |
| Anomaly agent alone | 0.745 | 0.624 | 0.351 | 0.449 | 0.088 | 0.172 | 0.005 |
| Payload agent alone | 0.577 | 1.000 | 0.396 | 0.567 | 0.000 | 0.355 | 0.000 |
| Behavior agent alone | 0.965 | 0.956 | 0.902 | 0.928 | 0.018 | 0.804 | 0.005 |
| Mode A without anomaly agent | 0.999 | 0.982 | 0.996 | 0.989 | 0.008 | 0.874 | 0.000 |
| Mode A without payload agent | 0.992 | 0.956 | 0.947 | 0.951 | 0.018 | 0.162 | 0.000 |
| Mode A without behavior agent | 0.920 | 0.983 | 0.393 | 0.562 | 0.003 | 0.320 | 0.000 |

## 2. Adaptive weights (RQ-7)

Weights learned from the first 1628 requests (15 update(s), 1 skipped), then both versions scored on the remaining 3799.

Final weights: anomaly 0.87, payload 0.96, behavior 1.17

| Version | PR-AUC | Recall (F/B) | False-alarm (F/B) |
|---|---|---|---|
| Mode A, equal weights | 1.000 | 0.996 | 0.003 |
| Mode A, adapted weights | 1.000 | 0.996 | 0.005 |

## 3. Detection rate by group (score ≥ 0.3)

| Method | Known attacks | Novel (held out) | Scanner | Normal (false alarms) |
|---|---|---|---|---|
| Mode A: confidence-weighted (ours) | 1.000 | 0.978 | 1.000 | 0.005 |
| Mode B: equal-weight average | 1.000 | 0.978 | 1.000 | 0.005 |
| Mode C: simple majority vote | 1.000 | 0.978 | 1.000 | 0.032 |
| Anomaly agent alone | 0.856 | 0.897 | 0.000 | 0.088 |
| Payload agent alone | 1.000 | 0.978 | 0.000 | 0.000 |
| Behavior agent alone | 0.738 | 0.775 | 1.000 | 0.018 |
| Mode A without anomaly agent | 1.000 | 0.978 | 1.000 | 0.008 |
| Mode A without payload agent | 0.844 | 0.891 | 1.000 | 0.018 |
| Mode A without behavior agent | 1.000 | 0.966 | 0.000 | 0.003 |

## 4. Confidence calibration

For each agent: requests grouped by the agent's confidence, and how often its own call (score ≥ 0.5) was right. A well-calibrated agent has accuracy close to its confidence. ECE = expected calibration error (lower is better).

**Anomaly agent** (ECE 0.159)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 0 | – | – |
| 0.2-0.4 | 184 | 0.353 | 0.630 |
| 0.4-0.6 | 502 | 0.507 | 0.737 |
| 0.6-0.8 | 1821 | 0.700 | 0.437 |
| 0.8-1.0 | 2920 | 0.917 | 0.992 |

**Payload agent** (ECE 0.156)

| Confidence | Requests | Mean confidence | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 0 | – | – |
| 0.2-0.4 | 2190 | 0.300 | 0.562 |
| 0.4-0.6 | 104 | 0.519 | 0.788 |
| 0.6-0.8 | 543 | 0.736 | 0.961 |
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
| Normal requests | 0.999 | 0.001 | 0.000 |
| Malicious requests | 0.017 | 0.728 | 0.256 |

- Normal traffic cleared by the fast filter: **98.7%** (an observation, not a target)
- Attacks the fast filter wrongly cleared: **1.2%**
- Decisions made in degraded mode (an agent timed out or failed): **0**
- Analysis path: p50 10.4 ms, p95 14.5 ms, p99 17.6 ms (target p95 ≤ 200 ms)
- Bypass path: p50 0.03 ms, p95 0.11 ms, p99 0.17 ms (target p95 ≤ 20 ms)

Per-stage latency (ms; fast filter over all requests, other stages over analysed requests):

| Stage | p50 | p95 | p99 |
|---|---|---|---|
| fast filter | 0.033 | 0.089 | 0.130 |
| agents | 10.261 | 14.386 | 17.377 |
| aggregation | 0.014 | 0.022 | 0.043 |
| explanation | 0.032 | 0.053 | 0.072 |

Latency here is in-process (no network) on the machine that ran this script.

Model file md5: `8b28c6c4b63e3b67ab5a40fc91239a20` · Python 3.13.16. Full config in `evaluation.json`.
