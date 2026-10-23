# Anomaly agent on SR-BH 2020 (real data)

Train 86149 normal · calibrate 18460 normal · test 63505 (45044 attacks) · 100 trees · seed 42

| Metric | Value |
|---|---|
| PR-AUC | 0.693 |
| ROC-AUC | 0.434 |
| Recall at 1% false-alarm | 0.010 |
| Recall at 5% false-alarm | 0.056 |
| Score ≥ 0.3: recall / false-alarm | 0.041 / 0.022 |
| Score ≥ 0.5: recall / false-alarm | 0.012 / 0.012 |
| Latency per request p50 / p95 | 0.54 / 0.81 ms |

## Detection by label (score ≥ 0.3)

| Label | Requests | Flagged |
|---|---|---|
| bruteforce | 171 | 0.368 |
| cmdi | 2570 | 0.277 |
| normal | 18461 | 0.022 |
| other_attack | 11202 | 0.065 |
| scanning | 368 | 0.014 |
| sqli | 28836 | 0.003 |
| traversal | 1897 | 0.128 |

## Confidence calibration

**ADD-25 as written (σ / σ_ref)** — ECE 0.187

| Confidence | Requests | Mean conf | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 28741 | 0.088 | 0.315 |
| 0.2-0.4 | 26840 | 0.294 | 0.355 |
| 0.4-0.6 | 6916 | 0.475 | 0.030 |
| 0.6-0.8 | 1008 | 0.652 | 0.000 |
| 0.8-1.0 | 0 | – | – |

**Proposed: σ rescaled p5–p95** — ECE 0.206

| Confidence | Requests | Mean conf | Accuracy |
|---|---|---|---|
| 0.0-0.2 | 18148 | 0.069 | 0.172 |
| 0.2-0.4 | 19002 | 0.296 | 0.455 |
| 0.4-0.6 | 17676 | 0.493 | 0.377 |
| 0.6-0.8 | 5985 | 0.683 | 0.057 |
| 0.8-1.0 | 2694 | 0.902 | 0.000 |

## Features that separate attacks from normal most (mean |z| gap)

Check these for dataset artefacts: SR-BH attacks come from scanners, so header features may separate the classes for reasons that will not hold on other traffic.

- method_code: 1.57
- total_length: 0.63
- payload_length: 0.59
- content_type_code: 0.24
- payload_entropy: 0.1
- query_length: 0.09
- digit_ratio: 0.09
- query_param_count: 0.08
