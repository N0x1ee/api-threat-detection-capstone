"""Decision engine: aggregation modes A/B/C, verdict bands, adaptive weights, explanations.

SRS v1.1 Sections 4.5, 5.7, 5.8 and 6. Every number comes from config.json.

    Mode A (default)  T = sum(w*c*s) / sum(w*c)       confidence-weighted
    Mode B            T = mean(s)                       equal-weight average
    Mode C            T = share of agents with s > 0.5  simple majority vote
"""
from __future__ import annotations

import math
import threading
import time
from collections import deque
from dataclasses import dataclass, field

AGENT_NAMES = ["anomaly", "payload", "behavior"]
AGENT_TITLES = {"anomaly": "Anomaly agent", "payload": "Payload agent", "behavior": "Behavior agent"}
ALLOW_BELOW, BLOCK_ABOVE = 0.3, 0.7          # defaults only; the live values come from config.json
MODE_NAMES = {"A": "confidence-weighted", "B": "equal-weight average", "C": "majority vote"}


# ------------------------------------------------------------------ aggregation
@dataclass
class Aggregation:
    score: float | None            # None = insufficient evidence (AI-040)
    mode: str
    numerator: float
    denominator: float
    contributions: dict = field(default_factory=dict)   # agent -> term it added to the numerator
    participants: list = field(default_factory=list)


def aggregate(results, weights, mode="A", vote_threshold=0.5, epsilon=1e-6):
    """results: {agent: AgentResult} for agents that returned a valid result."""
    names = [n for n in AGENT_NAMES if n in results] + [n for n in results if n not in AGENT_NAMES]
    if not names:
        return Aggregation(None, mode, 0.0, 0.0, {}, [])
    if mode == "A":
        terms = {n: weights.get(n, 1.0) * results[n].confidence * results[n].score for n in names}
        num = sum(terms.values())
        den = sum(weights.get(n, 1.0) * results[n].confidence for n in names)
        score = None if den < epsilon else num / den
    elif mode == "B":
        terms = {n: results[n].score / len(names) for n in names}
        num, den = sum(results[n].score for n in names), float(len(names))
        score = num / den
    elif mode == "C":
        terms = {n: (1.0 / len(names)) if results[n].score > vote_threshold else 0.0 for n in names}
        num, den = float(sum(results[n].score > vote_threshold for n in names)), float(len(names))
        score = num / den
    else:
        raise ValueError(f"unknown aggregation mode {mode!r}")
    if score is not None:
        if not -1e-9 <= score <= 1 + 1e-9:
            raise ArithmeticError(f"final score {score} outside [0, 1]")   # AI-039
        score = min(1.0, max(0.0, score))
    return Aggregation(score, mode, num, den, terms, names)


def combine(results, weights):
    """Mode A score only. Kept for older callers."""
    agg = aggregate(results, weights, "A")
    return agg.score if agg.score is not None else 0.0


def verdict_for(score, allow_below=ALLOW_BELOW, block_above=BLOCK_ABOVE):
    """Half-open bands (FR-042): ALLOW [0, t1), FLAG [t1, t2], BLOCK (t2, 1]."""
    if score < allow_below:
        return "ALLOW"
    return "FLAG" if score <= block_above else "BLOCK"


# ------------------------------------------------------------------ adaptive weights
def mcc(tp, fp, fn, tn):
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return (tp * tn - fp * fn) / den if den else 0.0


class WeightManager:
    """Agent weights from labelled outcomes (SRS 5.8, ADD-26).

    Every `update_every` new labels: perf_i = (MCC_i + 1) / 2 over the last `window` labels,
    target_i = perf_i / mean(perf), w_i <- clip((1 - alpha) * w_i + alpha * target_i, min, max),
    and no weight moves by more than `max_delta` in one update. Skipped (and logged) when the
    window holds fewer than `min_positives` attacks. Labels never come from the agents' own output.
    """

    def __init__(self, cfg=None, on_update=None):
        c = {"initial": 1.0, "min": 0.1, "max": 2.0, "alpha": 0.3, "max_delta": 0.2, "update_every": 1000,
             "window": 1000, "min_positives": 30, "use_analyst_labels": True, "frozen": False}
        c.update(cfg or {})
        self.cfg = c
        self.update_every = int(c["update_every"])
        self.on_update = on_update          # callback(entry) used by the pipeline to persist updates
        self.lock = threading.Lock()
        self.reset()

    def reset(self, weights=None):
        with self.lock:
            self.weights = dict(weights) if weights else {n: float(self.cfg["initial"]) for n in AGENT_NAMES}
            self.window = deque(maxlen=int(self.cfg["window"]))   # (label, {agent: predicted_attack}, provenance)
            self.seen = 0              # labels received
            self.since_update = 0
            self.updates = 0
            self.skipped = 0
            self.history = [dict(self.weights)]
            self.log = []

    @property
    def frozen(self):
        return bool(self.cfg["frozen"])

    def freeze(self, on=True):
        self.cfg["frozen"] = bool(on)

    def restore(self, weights):
        lo, hi = self.cfg["min"], self.cfg["max"]
        with self.lock:
            self.weights = {n: min(hi, max(lo, float(weights[n]))) for n in AGENT_NAMES}
            self.history.append(dict(self.weights))

    def feedback(self, scores, label, provenance="corpus", threshold=0.5):
        """scores: {agent: score}; label: 1 attack / 0 normal; provenance: 'corpus' or 'analyst'."""
        if provenance == "analyst" and not self.cfg["use_analyst_labels"]:
            return None
        with self.lock:
            preds = {n: scores[n] >= threshold for n in scores if n in AGENT_NAMES}
            self.window.append((int(bool(label)), preds, provenance))
            self.seen += 1
            self.since_update += 1
            if self.since_update < self.update_every or self.frozen:
                return None
            self.since_update = 0
            return self._update()

    def _confusion(self, name):
        tp = fp = fn = tn = 0
        for y, preds, _ in self.window:
            if name not in preds:
                continue
            p = preds[name]
            tp += p and y
            fp += p and not y
            fn += (not p) and y
            tn += (not p) and (not y)
        return tp, fp, fn, tn

    def _update(self):
        positives = sum(y for y, _, _ in self.window)
        prov = {"corpus": sum(p == "corpus" for *_, p in self.window), "analyst": sum(p == "analyst" for *_, p in self.window)}
        entry = {"ts": time.time(), "old": dict(self.weights), "window": len(self.window),
                 "positives": positives, "provenance": prov}
        if positives < self.cfg["min_positives"]:
            self.skipped += 1
            entry.update(skipped=True, reason=f"only {positives} attacks in window (< {self.cfg['min_positives']})",
                         new=dict(self.weights))
        else:
            m = {n: mcc(*self._confusion(n)) for n in AGENT_NAMES}
            perf = {n: (m[n] + 1) / 2 for n in AGENT_NAMES}
            mean_perf = sum(perf.values()) / len(perf)
            a, lo, hi, dmax = self.cfg["alpha"], self.cfg["min"], self.cfg["max"], self.cfg["max_delta"]
            new = {}
            for n in AGENT_NAMES:
                target = perf[n] / mean_perf if mean_perf > 0 else 1.0
                w = (1 - a) * self.weights[n] + a * target
                w = max(self.weights[n] - dmax, min(self.weights[n] + dmax, w))
                new[n] = max(lo, min(hi, w))
            self.weights = new
            self.updates += 1
            self.history.append(dict(new))
            entry.update(skipped=False, mcc=m, new=dict(new))
        self.log.append(entry)
        if self.on_update:
            try:
                self.on_update(entry)
            except Exception:      # persistence problems must not break detection
                pass
        return entry

    def snapshot(self):
        with self.lock:
            acc = {}
            mccs = {}
            for n in AGENT_NAMES:
                tp, fp, fn, tn = self._confusion(n)
                tot = tp + fp + fn + tn
                acc[n] = (tp + tn) / tot if tot else None
                mccs[n] = round(mcc(tp, fp, fn, tn), 3) if tot else None
            return {"weights": dict(self.weights), "accuracy": acc, "mcc": mccs, "labelled": self.seen,
                    "updates": self.updates, "skipped": self.skipped, "update_every": self.update_every,
                    "frozen": self.frozen, "bounds": [self.cfg["min"], self.cfg["max"]],
                    "history": list(self.history[-30:]), "last_update": self.log[-1] if self.log else None}


# ------------------------------------------------------------------ explanations
ATTACK_LABEL = {
    "sqli": "SQL injection attempt", "xss": "Cross-site scripting (XSS) attempt",
    "cmdi": "OS command injection attempt", "traversal": "Path traversal attempt",
    "recon": "Automated scanning / reconnaissance", "anomaly": "Unusual request structure",
    "suspicious": "Suspicious request", "normal": "Normal traffic", "unknown": "Not analysed",
}


def classify(results, final):
    p, b, a = results.get("payload"), results.get("behavior"), results.get("anomaly")
    if p and p.score >= 0.5:
        return p.detail.get("attack_type", "suspicious")
    if b and b.score >= 0.5:
        return "recon"
    if a and a.score >= 0.5:
        return "anomaly"
    if final is None:
        return "unknown"
    return "suspicious" if final >= ALLOW_BELOW else "normal"


def explain(results, weights, final, verdict, fast_reasons, agg=None, excluded=None,
            thresholds=(ALLOW_BELOW, BLOCK_ABOVE), policy_used=None):
    """Structured + plain-English explanation built only from this decision's values (XAI-001..013)."""
    excluded = excluded or {}
    t1, t2 = thresholds
    atype = classify(results, final)
    contrib = (agg.contributions if agg else
               {n: weights.get(n, 1.0) * r.confidence * r.score for n, r in results.items()})
    lead = max(contrib, key=contrib.get) if contrib and max(contrib.values()) > 0 else None

    evidence = []
    for n in ("payload", "anomaly", "behavior"):
        r = results.get(n)
        if r and r.score >= 0.3 and r.detail.get("reason"):
            evidence.append(f"{AGENT_TITLES[n]}: {r.detail['reason']}")
    quiet = [AGENT_TITLES[n] for n, r in results.items() if r.score < 0.3]
    if quiet:
        evidence.append(f"Saw nothing unusual: {', '.join(quiet)}.")
    if excluded:
        evidence.append("Did not take part: " + "; ".join(f"{AGENT_TITLES.get(n, n)} ({why})" for n, why in excluded.items()) + ".")
    if fast_reasons:
        evidence.append("Fast filter sent this to the AI agents because: " + "; ".join(fast_reasons) + ".")

    label = ATTACK_LABEL.get(atype, atype)
    if policy_used:
        summary = (f"{verdict} by failure policy: no agent produced a usable result ({policy_used}). "
                   "Forwarded and marked for review." if verdict == "FLAG" else
                   f"{verdict} by failure policy: no agent produced a usable result ({policy_used}).")
        action = "Check agent health, then review this request."
    elif verdict == "BLOCK":
        summary = (f"Blocked: {label}. Threat score {final:.2f} (block above {t2}). "
                   f"Strongest alarm came from the {AGENT_TITLES[lead].lower() if lead else 'agents'}.")
        action = "Block this request. Review the user and IP for repeated attempts."
    elif verdict == "FLAG":
        summary = f"Flagged for review: {label.lower()}. Threat score {final:.2f} (between {t1} and {t2}). The agents were not fully sure."
        action = "Hold for an analyst. Use the review queue to confirm or clear it."
    else:
        summary = f"Allowed. Threat score {final:.2f} (allow below {t1}). The AI agents checked this request and found it normal."
        action = "No action needed."
    if excluded and not policy_used:
        summary += f" Degraded mode: {len(excluded)} agent(s) missing."

    structured = {
        "final_score": final, "verdict": verdict, "thresholds": {"allow_below": t1, "block_above": t2},
        "mode": agg.mode if agg else "A", "mode_name": MODE_NAMES.get(agg.mode if agg else "A"),
        "numerator": agg.numerator if agg else None, "denominator": agg.denominator if agg else None,
        "agents": {n: {"score": round(r.score, 4), "confidence": round(r.confidence, 4),
                       "weight": round(weights.get(n, 1.0), 4), "contribution": round(contrib.get(n, 0.0), 4),
                       "evidence": r.detail.get("reason", "")} for n, r in results.items()},
        "excluded": excluded, "lead_agent": lead, "attack_type": atype,
        "failure_policy": policy_used, "insufficient_evidence": bool(agg and agg.score is None and results),
    }
    return {"summary": summary, "evidence": evidence, "action": action, "attack_type": atype,
            "lead_agent": lead, "structured": structured}
