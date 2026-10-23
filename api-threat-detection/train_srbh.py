"""Train and evaluate the anomaly agent on real SR-BH 2020 data.

    python train_srbh.py                 # full data
    python train_srbh.py --sample 20000  # quick run on a subsample of each split

Train: SR-BH train-split NORMAL rows only (AI-015). Calibrate: val-split normal rows (AI-016).
Test: the whole test split. Writes models/anomaly_srbh.joblib and results/srbh_anomaly.md.
"""
import argparse
import json
import os
import random
import time

import joblib
import numpy as np
from sklearn.metrics import average_precision_score, roc_auc_score

from app.agents import FEATURES, AnomalyAgent, extract_features
from app.srbh import DEFAULT_PATH, load

HERE = os.path.dirname(os.path.abspath(__file__))


def ece(conf, correct, bins=5):
    conf, correct = np.asarray(conf), np.asarray(correct, dtype=float)
    total, rows = 0.0, []
    for i in range(bins):
        lo, hi = i / bins, (i + 1) / bins
        m = (conf >= lo) & ((conf < hi) if i < bins - 1 else (conf <= hi))
        if m.any():
            total += m.mean() * abs(conf[m].mean() - correct[m].mean())
            rows.append((f"{lo:.1f}-{hi:.1f}", int(m.sum()), conf[m].mean(), correct[m].mean()))
        else:
            rows.append((f"{lo:.1f}-{hi:.1f}", 0, None, None))
    return total, rows


def recall_at_fpr(y, s, fpr):
    thr = np.percentile(s[y == 0], 100 * (1 - fpr))
    return float((s[y == 1] > thr).mean()), float(thr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default=DEFAULT_PATH)
    ap.add_argument("--sample", type=int, default=0, help="max rows per split (0 = all)")
    ap.add_argument("--trees", type=int, default=100)
    ap.add_argument("--seed", type=int, default=42)
    a = ap.parse_args()

    t0 = time.time()
    data = load(a.data)
    rng = random.Random(a.seed)
    if a.sample:
        data = {k: sorted(rng.sample(v, min(a.sample, len(v))), key=lambda r: 0) for k, v in data.items()}
    train_n = [r for r in data["train"] if not r["is_attack"]]
    val_n = [r for r in data["val"] if not r["is_attack"]]
    test = data["test"]
    print(f"Loaded in {time.time() - t0:.0f}s: train normal {len(train_n)}, val normal {len(val_n)}, test {len(test)}")

    t1 = time.time()
    agent = AnomalyAgent(n_estimators=a.trees, random_state=a.seed).fit(train_n, validation=val_n)
    fit_s = time.time() - t1
    print(f"Trained in {fit_s:.1f}s")

    X = np.array([extract_features(r) for r in test], dtype=float)
    y = np.array([r["is_attack"] for r in test])
    labels = np.array([r["label"] for r in test])
    T = agent.tree_scores(X)
    raw = 2.0 ** np.log2(T).mean(1)
    score = 1.0 / (1.0 + np.exp(-np.clip((raw - agent.t) / agent.k, -30, 30)))
    sigma = T.std(1)
    conf = {m: np.array([(setattr(agent, "confidence_mode", m) or agent.confidence_from_spread(s)) for s in sigma])
            for m in ("ref", "range")}
    agent.confidence_mode = "ref"

    lat = []
    for r in test[:500]:
        s0 = time.perf_counter()
        agent.analyze(r)
        lat.append((time.perf_counter() - s0) * 1000)

    pred = score >= 0.5
    correct = pred == (y == 1)
    r1, _ = recall_at_fpr(y, score, 0.01)
    r5, _ = recall_at_fpr(y, score, 0.05)
    res = {
        "rows": {"train_normal": len(train_n), "val_normal": len(val_n), "test": len(test),
                 "test_attacks": int(y.sum())},
        "pr_auc": float(average_precision_score(y, score)), "roc_auc": float(roc_auc_score(y, score)),
        "recall_at_1pct_fpr": r1, "recall_at_5pct_fpr": r5,
        "at_0.3": {"recall": float((score[y == 1] >= 0.3).mean()), "fpr": float((score[y == 0] >= 0.3).mean())},
        "at_0.5": {"recall": float((score[y == 1] >= 0.5).mean()), "fpr": float((score[y == 0] >= 0.5).mean())},
        "per_label": {l: {"n": int((labels == l).sum()), "flagged_0.3": float((score[labels == l] >= 0.3).mean())}
                      for l in sorted(set(labels))},
        "calibration": {m: ece(c, correct)[0] for m, c in conf.items()},
        "latency_ms": {"p50": float(np.percentile(lat, 50)), "p95": float(np.percentile(lat, 95))},
        "fit_seconds": fit_s, "trees": a.trees, "seed": a.seed, "sample": a.sample,
        "sigma_ref": agent.sigma_ref, "sigma_lo": agent.sigma_lo, "t": agent.t, "k": agent.k,
    }
    # Which features separate the classes most (mean |z| of attacks vs normal) - a leakage check
    z = np.abs((X - agent.mu) / agent.sd)
    gap = z[y == 1].mean(0) - z[y == 0].mean(0)
    res["feature_gap"] = {FEATURES[i]: round(float(gap[i]), 2) for i in np.argsort(-gap)[:8]}

    os.makedirs(os.path.join(HERE, "models"), exist_ok=True)
    os.makedirs(os.path.join(HERE, "results"), exist_ok=True)
    joblib.dump(agent, os.path.join(HERE, "models", "anomaly_srbh.joblib"))
    with open(os.path.join(HERE, "results", "srbh_anomaly.json"), "w") as f:
        json.dump(res, f, indent=2)
    md = report(res, conf, correct)
    with open(os.path.join(HERE, "results", "srbh_anomaly.md"), "w") as f:
        f.write(md)
    print(md)


def report(r, conf, correct):
    L = ["# Anomaly agent on SR-BH 2020 (real data)", "",
         f"Train {r['rows']['train_normal']} normal · calibrate {r['rows']['val_normal']} normal · "
         f"test {r['rows']['test']} ({r['rows']['test_attacks']} attacks) · {r['trees']} trees · seed {r['seed']}"
         + (f" · sample {r['sample']}/split" if r["sample"] else ""), "",
         "| Metric | Value |", "|---|---|",
         f"| PR-AUC | {r['pr_auc']:.3f} |", f"| ROC-AUC | {r['roc_auc']:.3f} |",
         f"| Recall at 1% false-alarm | {r['recall_at_1pct_fpr']:.3f} |",
         f"| Recall at 5% false-alarm | {r['recall_at_5pct_fpr']:.3f} |",
         f"| Score ≥ 0.3: recall / false-alarm | {r['at_0.3']['recall']:.3f} / {r['at_0.3']['fpr']:.3f} |",
         f"| Score ≥ 0.5: recall / false-alarm | {r['at_0.5']['recall']:.3f} / {r['at_0.5']['fpr']:.3f} |",
         f"| Latency per request p50 / p95 | {r['latency_ms']['p50']:.2f} / {r['latency_ms']['p95']:.2f} ms |",
         "", "## Detection by label (score ≥ 0.3)", "", "| Label | Requests | Flagged |", "|---|---|---|"]
    L += [f"| {l} | {v['n']} | {v['flagged_0.3']:.3f} |" for l, v in r["per_label"].items()]
    L += ["", "## Confidence calibration", ""]
    for m, c in conf.items():
        e, rows = ece(c, correct)
        name = "ADD-25 as written (σ / σ_ref)" if m == "ref" else "Proposed: σ rescaled p5–p95"
        L += [f"**{name}** — ECE {e:.3f}", "", "| Confidence | Requests | Mean conf | Accuracy |", "|---|---|---|---|"]
        L += [f"| {b} | {n} | " + ("– | – |" if mc is None else f"{mc:.3f} | {acc:.3f} |") for b, n, mc, acc in rows]
        L.append("")
    L += ["## Features that separate attacks from normal most (mean |z| gap)", "",
          "Check these for dataset artefacts: SR-BH attacks come from scanners, so header features may separate "
          "the classes for reasons that will not hold on other traffic.", ""]
    L += [f"- {k}: {v}" for k, v in r["feature_gap"].items()]
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
