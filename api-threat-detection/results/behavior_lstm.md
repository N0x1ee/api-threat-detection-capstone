# Behaviour LSTM — results (synthetic sessions, test seed never seen in training)

Accuracy (4 classes): **0.982** · temperature T = 0.95 · ECE 0.007 · NumPy vs Keras max logit difference 3.4e-06

| true \ predicted | benign | scanning | credential_stuffing | scraping |
|---|---|---|---|---|
| benign | 8593 | 4 | 160 | 1 |
| scanning | 7 | 3507 | 1 | 3 |
| credential_stuffing | 101 | 0 | 2445 | 0 |
| scraping | 25 | 0 | 0 | 2261 |

| Attack vs benign | PR-AUC |
|---|---|
| LSTM | 0.999 |
| Markov baseline (AI-072) | 0.682 |

| History length | Attacks detected (score ≥ 0.5) | Benign false alarms |
|---|---|---|
| len 1-2 | 0.867 | 0.058 |
| len 3-5 | 0.999 | 0.000 |
| len 6-10 | 1.000 | 0.000 |
| len 11-20 | 1.000 | 0.000 |

Short histories are ambiguous by design: one login attempt looks the same from a user and an attacker. That is why confidence is multiplied by h = min(1, events/5).
