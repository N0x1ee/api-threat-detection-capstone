"""Replay evaluation (SRS v1.1 FR-089 to FR-097, FR-111, FR-112, Section 12.2).

    python evaluate.py                    # default config.json
    python evaluate.py --config my.json   # any other config
    python evaluate.py --seed 99          # different test traffic

Writes results/evaluation.md (for people) and results/evaluation.json (for scripts).

What it reports, all on the same test requests:
  1. Each aggregation mode (A confidence-weighted, B equal average, C majority vote),
     each agent alone, and mode A with each agent switched off (ablation).
     PR-AUC plus precision / recall / F1 / false-alarm rate at the two live operating points:
       "FLAG or BLOCK" = score >= allow_below    "BLOCK only" = score > block_above
     (the same thresholds the gateway uses - no separate 0.5 cut-off).
  2. Mode A with weights adapted on a warm-up slice vs fixed equal weights (RQ-7).
  3. Detection by attack group: known, novel (held out from training), scanner.
  4. Confidence calibration per agent (reliability table, plus a PNG if matplotlib is installed).
  5. The full live pipeline: fast filter + agents + verdicts, and latency.

Data note: the agents in this version are still the prototype models trained on the synthetic
generator, and the test traffic comes from the same generator. Treat these numbers as a check that
the pipeline and the evaluation work, not as research results. Real-data results come once the
CNN/LSTM agents are trained on SR-BH + generator data.
"""
import argparse
import hashlib
import json
import os
import platform
import random
import time

from sklearn.metrics import average_precision_score, roc_auc_score

from app.config import load_config
from app.decision import AGENT_NAMES, WeightManager, aggregate
from app.pipeline import Pipeline
from app.traffic import ATTACK_KINDS, generate_session
from app.training import MODEL_PATH, load_or_train

ROOT = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(ROOT, "results")


# ------------------------------------------------------------------ data
def build_test_set(seed=99):
    rng = random.Random(seed)
    reqs, t = [], 0.0
    plan = [("normal", False)] * 500
    for k in ATTACK_KINDS:
        plan += [(k, False)] * 80 + [(k, True)] * 80
    plan += [("recon", False)] * 60
    rng.shuffle(plan)
    for kind, novel in plan:
        s = generate_session(rng, kind, t, novel)
        for r in s:
            r["novel"] = r.get("novel", False) and r["label"] == 1
        reqs += s
        t = s[-1]["ts"] + 1
    return reqs


def group_of(req):
    if req["label"] == 0:
        return "normal"
    if req.get("attack_type") == "recon":
        return "scanner"
    return "novel" if req.get("novel") else "known"


# ------------------------------------------------------------------ metrics
def confusion(labels, preds):
    tp = sum(p and y for p, y in zip(preds, labels))
    fp = sum(p and not y for p, y in zip(preds, labels))
    fn = sum((not p) and y for p, y in zip(preds, labels))
    tn = sum((not p) and (not y) for p, y in zip(preds, labels))
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": prec, "recall": rec, "f1": 2 * prec * rec / (prec + rec) if prec + rec else 0.0,
            "fpr": fp / (fp + tn) if fp + tn else 0.0, "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def score_metrics(labels, scores, t1, t2):
    out = {"pr_auc": average_precision_score(labels, scores) if len(set(labels)) > 1 else None,
           "roc_auc": roc_auc_score(labels, scores) if len(set(labels)) > 1 else None}
    out["flag_or_block"] = confusion(labels, [s >= t1 for s in scores])
    out["block_only"] = confusion(labels, [s > t2 for s in scores])
    return out


def reliability(rows, agent, bins=5):
    """Bucket the agent's confidence and compare with how often its own call (score >= 0.5) was right."""
    table = []
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        sel = [r for r in rows if agent in r["res"] and (lo <= r["res"][agent].confidence < hi
                                                         or (b == bins - 1 and r["res"][agent].confidence == 1.0))]
        if not sel:
            table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": 0, "mean_confidence": None, "accuracy": None})
            continue
        acc = sum((r["res"][agent].score >= 0.5) == bool(r["label"]) for r in sel) / len(sel)
        conf = sum(r["res"][agent].confidence for r in sel) / len(sel)
        table.append({"bin": f"{lo:.1f}-{hi:.1f}", "n": len(sel), "mean_confidence": conf, "accuracy": acc})
    n = sum(t["n"] for t in table)
    ece = sum(t["n"] / n * abs(t["accuracy"] - t["mean_confidence"]) for t in table if t["n"]) if n else None
    return table, ece


def file_md5(path):
    if not os.path.exists(path):
        return None
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default=None)
    ap.add_argument("--seed", type=int, default=99)
    ap.add_argument("--warmup", type=float, default=0.3, help="share of test requests used to adapt weights")
    ap.add_argument("--behavior", choices=["markov", "lstm"], default="lstm")
    args = ap.parse_args()

    cfg = load_config(args.config)
    t1, t2 = cfg["thresholds"]["allow_below"], cfg["thresholds"]["block_above"]
    agg_cfg = cfg["aggregation"]
    agents = load_or_train()
    if args.behavior == "lstm":                    # primary behaviour model (AI-026) instead of Markov
        from app.behavior_lstm import LSTMBehaviorAgent
        agents = (agents[0], agents[1], LSTMBehaviorAgent(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                                         "weights", "behavior_lstm.npz")))
    # generous timeout here: evaluation measures detection, latency is measured separately below
    eval_cfg = load_config(args.config, overrides={"agents": {"timeout_ms": 10_000, "disabled": []}})
    pipe = Pipeline(agents, ":memory:", cfg=eval_cfg)

    reqs = build_test_set(args.seed)
    print(f"Test set: {len(reqs)} requests ({sum(r['label'] for r in reqs)} malicious). Running agents...")
    rows, t0 = [], time.time()
    for req in reqs:
        rec = pipe.process(req, force_ai=True, log=False)
        rows.append({"req": req, "rec": rec, "res": rec["results"], "label": req["label"], "group": group_of(req)})
    print(f"Agents done in {time.time() - t0:.1f}s")

    equal = {n: float(cfg["weights"]["initial"]) for n in AGENT_NAMES}

    def agg_score(r, mode, weights=equal, drop=()):
        res = {n: v for n, v in r["res"].items() if n not in drop}
        a = aggregate(res, weights, mode, agg_cfg["vote_threshold"], agg_cfg["epsilon"])
        return 0.5 if a.score is None else a.score     # fail-open FLAG counts as a mid score

    methods = {
        "Mode A: confidence-weighted mean": lambda r: agg_score(r, "A"),
        "Mode B: equal-weight average": lambda r: agg_score(r, "B"),
        "Mode C: simple majority vote": lambda r: agg_score(r, "C"),
        "Mode D: confidence-weighted noisy-OR (default)": lambda r: agg_score(r, "D"),
        **{f"{n.capitalize()} agent alone": (lambda r, n=n: r["res"][n].score) for n in AGENT_NAMES},
        **{f"Mode A without {n} agent": (lambda r, n=n: agg_score(r, "A", drop=(n,))) for n in AGENT_NAMES},
    }
    labels = [r["label"] for r in rows]
    report = {"methods": {}, "groups": {}}
    for name, fn in methods.items():
        report["methods"][name] = score_metrics(labels, [fn(r) for r in rows], t1, t2)
        report["groups"][name] = {g: (sum(fn(r) >= t1 for r in rows if r["group"] == g) /
                                      max(1, sum(r["group"] == g for r in rows)))
                                  for g in ("known", "novel", "scanner", "normal")}

    # adaptive weights: learn on the warm-up slice, evaluate both versions on the rest
    cut = int(len(rows) * args.warmup)
    wm = WeightManager(dict(cfg["weights"], frozen=False))
    for r in rows[:cut]:
        wm.feedback({n: v.score for n, v in r["res"].items()}, r["label"], "corpus")
    rest = rows[cut:]
    rest_labels = [r["label"] for r in rest]
    adaptive = {
        "Mode A, equal weights": score_metrics(rest_labels, [agg_score(r, "A") for r in rest], t1, t2),
        "Mode A, adapted weights": score_metrics(rest_labels, [agg_score(r, "A", wm.weights) for r in rest], t1, t2),
    }
    report["adaptive"] = {"warmup_requests": cut, "evaluated_requests": len(rest), "final_weights": wm.weights,
                          "updates": wm.updates, "skipped": wm.skipped, "results": adaptive}

    report["calibration"] = {}
    for n in AGENT_NAMES:
        table, ece = reliability(rows, n)
        report["calibration"][n] = {"bins": table, "ece": ece}

    # full live pipeline with the real config (fast filter, thresholds, timeouts)
    live = Pipeline(agents, ":memory:", cfg=cfg)
    live_rows = [(r, live.process(r, log=False)) for r in reqs]
    normal = [rec for r, rec in live_rows if r["label"] == 0]
    attacks = [rec for r, rec in live_rows if r["label"] == 1]
    share = lambda grp, v: sum(x["verdict"] == v for x in grp) / len(grp)
    ai_lat = sorted(x["latency_ms"] for x in normal + attacks if x["route"] == "ai")
    fast_lat = sorted(x["latency_ms"] for x in normal + attacks if x["route"] == "fast")
    pct = lambda xs, p: xs[min(len(xs) - 1, int(len(xs) * p))] if xs else None
    report["pipeline"] = {
        "normal": {v: share(normal, v) for v in ("ALLOW", "FLAG", "BLOCK")},
        "malicious": {v: share(attacks, v) for v in ("ALLOW", "FLAG", "BLOCK")},
        "fast_filter_bypass_normal": sum(x["route"] == "fast" for x in normal) / len(normal),
        "fast_filter_missed_attacks": sum(x["route"] == "fast" for x in attacks) / len(attacks),
        "degraded_decisions": sum(bool(x["degraded"]) for x in normal + attacks),
        "stage_latency_ms": {k: Pipeline._pcts([x["timings"].get(k) for x in normal + attacks
                                                if x["route"] == "ai" or k == "fast_filter"])
                             for k in ("fast_filter", "agents", "aggregation", "explanation")},
        "latency_ms": {"analysis": {"p50": pct(ai_lat, .5), "p95": pct(ai_lat, .95), "p99": pct(ai_lat, .99)},
                       "bypass": {"p50": pct(fast_lat, .5), "p95": pct(fast_lat, .95), "p99": pct(fast_lat, .99)}},
    }
    report["run"] = {"seed": args.seed, "requests": len(reqs), "malicious": sum(labels),
                     "config": cfg, "model_file_md5": file_md5(MODEL_PATH),
                     "python": platform.python_version(), "when": time.strftime("%Y-%m-%d %H:%M:%S")}

    os.makedirs(RESULTS, exist_ok=True)
    with open(os.path.join(RESULTS, "evaluation.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, default=float)
    md = to_markdown(report, t1, t2)
    with open(os.path.join(RESULTS, "evaluation.md"), "w", encoding="utf-8") as f:
        f.write(md)
    plot_reliability(report["calibration"])
    print("\n" + md)


# ------------------------------------------------------------------ output
def _f(x, d=3):
    return "–" if x is None else f"{x:.{d}f}"


def to_markdown(rep, t1, t2):
    run = rep["run"]
    L = ["# Evaluation results", "",
         f"Seed {run['seed']} · {run['requests']} requests ({run['malicious']} malicious) · "
         f"thresholds allow < {t1}, block > {t2} · mode {run['config']['aggregation']['mode']} · {run['when']}", "",
         "> These agents are still the prototype models, trained and tested on the synthetic generator. "
         "The numbers check that the pipeline and evaluation work; they are not research results yet.", "",
         "## 1. Methods compared (every request analysed by the agents)", "",
         "PR-AUC uses the raw score. The other columns use the live thresholds: "
         f"**FLAG or BLOCK** = score ≥ {t1}, **BLOCK only** = score > {t2}.", "",
         "| Method | PR-AUC | Precision (F/B) | Recall (F/B) | F1 (F/B) | False-alarm (F/B) | Recall (BLOCK) | False-alarm (BLOCK) |",
         "|---|---|---|---|---|---|---|---|"]
    for name, m in rep["methods"].items():
        fb, b = m["flag_or_block"], m["block_only"]
        L.append(f"| {name} | {_f(m['pr_auc'])} | {_f(fb['precision'])} | {_f(fb['recall'])} | {_f(fb['f1'])} | "
                 f"{_f(fb['fpr'])} | {_f(b['recall'])} | {_f(b['fpr'])} |")
    L += ["", "## 2. Adaptive weights (RQ-7)", "",
          f"Weights learned from the first {rep['adaptive']['warmup_requests']} requests "
          f"({rep['adaptive']['updates']} update(s), {rep['adaptive']['skipped']} skipped), "
          f"then both versions scored on the remaining {rep['adaptive']['evaluated_requests']}.", "",
          "Final weights: " + ", ".join(f"{n} {w:.2f}" for n, w in rep["adaptive"]["final_weights"].items()), "",
          "| Version | PR-AUC | Recall (F/B) | False-alarm (F/B) |", "|---|---|---|---|"]
    for name, m in rep["adaptive"]["results"].items():
        L.append(f"| {name} | {_f(m['pr_auc'])} | {_f(m['flag_or_block']['recall'])} | {_f(m['flag_or_block']['fpr'])} |")
    L += ["", f"## 3. Detection rate by group (score ≥ {t1})", "",
          "| Method | Known attacks | Novel (held out) | Scanner | Normal (false alarms) |", "|---|---|---|---|---|"]
    for name, g in rep["groups"].items():
        L.append(f"| {name} | {_f(g['known'])} | {_f(g['novel'])} | {_f(g['scanner'])} | {_f(g['normal'])} |")
    L += ["", "## 4. Confidence calibration", "",
          "For each agent: requests grouped by the agent's confidence, and how often its own call "
          "(score ≥ 0.5) was right. A well-calibrated agent has accuracy close to its confidence. "
          "ECE = expected calibration error (lower is better).", ""]
    for n, c in rep["calibration"].items():
        L.append(f"**{n.capitalize()} agent** (ECE {_f(c['ece'])})")
        L += ["", "| Confidence | Requests | Mean confidence | Accuracy |", "|---|---|---|---|"]
        for b in c["bins"]:
            L.append(f"| {b['bin']} | {b['n']} | {_f(b['mean_confidence'])} | {_f(b['accuracy'])} |")
        L.append("")
    p = rep["pipeline"]
    la, lb = p["latency_ms"]["analysis"], p["latency_ms"]["bypass"]
    L += ["## 5. Full live pipeline (fast filter + agents + thresholds)", "",
          "| | ALLOW | FLAG | BLOCK |", "|---|---|---|---|",
          f"| Normal requests | {_f(p['normal']['ALLOW'])} | {_f(p['normal']['FLAG'])} | {_f(p['normal']['BLOCK'])} |",
          f"| Malicious requests | {_f(p['malicious']['ALLOW'])} | {_f(p['malicious']['FLAG'])} | {_f(p['malicious']['BLOCK'])} |",
          "",
          f"- Normal traffic cleared by the fast filter: **{p['fast_filter_bypass_normal'] * 100:.1f}%** (an observation, not a target)",
          f"- Attacks the fast filter wrongly cleared: **{p['fast_filter_missed_attacks'] * 100:.1f}%**",
          f"- Decisions made in degraded mode (an agent timed out or failed): **{p['degraded_decisions']}**",
          f"- Analysis path: p50 {_f(la['p50'], 1)} ms, p95 {_f(la['p95'], 1)} ms, p99 {_f(la['p99'], 1)} ms (target p95 ≤ 200 ms)",
          f"- Bypass path: p50 {_f(lb['p50'], 2)} ms, p95 {_f(lb['p95'], 2)} ms, p99 {_f(lb['p99'], 2)} ms (target p95 ≤ 20 ms)",
          "", "Per-stage latency (ms; fast filter over all requests, other stages over analysed requests):", "",
          "| Stage | p50 | p95 | p99 |", "|---|---|---|---|",
          *[f"| {k.replace('_', ' ')} | {_f(v['p50'], 3)} | {_f(v['p95'], 3)} | {_f(v['p99'], 3)} |"
            for k, v in p["stage_latency_ms"].items() if v],
          "", "Latency here is in-process (no network) on the machine that ran this script.",
          "", f"Model file md5: `{run['model_file_md5']}` · Python {run['python']}. Full config in `evaluation.json`.", ""]
    return "\n".join(L)


def plot_reliability(cal):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("(matplotlib not installed - skipped results/reliability.png)")
        return
    colors = {"anomaly": "#2a78d6", "payload": "#eb6834", "behavior": "#1baf7a"}
    fig, ax = plt.subplots(figsize=(5, 4.2), dpi=150)
    ax.plot([0, 1], [0, 1], color="#a3a29a", lw=1, ls="--", label="perfect calibration")
    for n, c in cal.items():
        pts = [(b["mean_confidence"], b["accuracy"]) for b in c["bins"] if b["n"]]
        if pts:
            ax.plot(*zip(*pts), marker="o", ms=5, lw=2, color=colors.get(n), label=f"{n} (ECE {_f(c['ece'], 2)})")
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("Mean confidence in bin")
    ax.set_ylabel("Accuracy in bin")
    ax.set_title("Agent confidence calibration", fontsize=10)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.grid(color="#e6e5df", lw=0.6)
    ax.legend(frameon=False, fontsize=8, loc="lower right")
    fig.tight_layout()
    fig.savefig(os.path.join(RESULTS, "reliability.png"))
    print("Wrote results/reliability.png")


if __name__ == "__main__":
    main()
