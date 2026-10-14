"""The three specialised agents. Each returns: score (0-1 threat), confidence (0-1), detail."""
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .traffic import normalize_text

FEATURES = ["payload_length", "entropy", "special_char_ratio", "digit_ratio", "uppercase_ratio",
            "percent_signs", "single_quotes", "angle_brackets", "shell_symbols",
            "header_count", "user_agent_length"]


@dataclass
class AgentResult:
    name: str
    score: float
    confidence: float
    detail: dict = field(default_factory=dict)


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))


# ------------------------------------------------------------------ Agent 1
def extract_features(req):
    raw = (req.get("query") or "") + " " + (req.get("body") or "")
    dec = normalize_text(raw).strip()
    n = len(dec)
    if n:
        counts = Counter(dec)
        entropy = -sum(c / n * math.log2(c / n) for c in counts.values())
        special = sum(1 for ch in dec if not ch.isalnum() and not ch.isspace()) / n
        digit = sum(ch.isdigit() for ch in dec) / n
        upper = sum(ch.isupper() for ch in dec) / n
    else:
        entropy = special = digit = upper = 0.0
    h = req.get("headers") or {}
    return [n, entropy, special, digit, upper, raw.count("%"), dec.count("'"),
            dec.count("<") + dec.count(">"), sum(dec.count(c) for c in ";|`$()\\"),
            len(h), len(h.get("User-Agent", ""))]


class AnomalyAgent:
    """Isolation Forest trained on NORMAL traffic only. Flags statistical outliers."""
    name = "anomaly"

    def fit(self, reqs):
        X = np.array([extract_features(r) for r in reqs], dtype=float)
        self.mu = X.mean(0)
        self.sd = np.maximum(X.std(0), 0.2)
        self.model = IsolationForest(n_estimators=100, random_state=42).fit(X)
        raw = -self.model.score_samples(X)
        self.t = float(np.percentile(raw, 98))
        self.k = max(1e-3, float(np.percentile(raw, 99.9) - np.percentile(raw, 50)) / 4)
        return self

    def analyze(self, req):
        x = np.array([extract_features(req)], dtype=float)
        raw = float(-self.model.score_samples(x)[0])
        score = _sigmoid((raw - self.t) / self.k)
        conf = min(1.0, 0.3 + abs(score - 0.5) * 1.4)
        reason = ""
        if score >= 0.3:
            z = (x[0] - self.mu) / self.sd
            top = [i for i in np.argsort(-np.abs(z))[:3] if abs(z[i]) >= 3]
            parts = [f"{FEATURES[i]} = {x[0][i]:.2f} (normal is about {self.mu[i]:.2f})" for i in top]
            reason = "Request shape is unusual: " + "; ".join(parts) + "." if parts else \
                "Request shape is statistically unusual compared with normal traffic."
        return AgentResult(self.name, float(score), float(conf), {"reason": reason, "raw": raw})


# ------------------------------------------------------------------ Agent 2
class PayloadAgent:
    """Character n-gram model over the payload. Reads raw text, finds attack signatures.
    (Lightweight stand-in for the proposal's character-level CNN - see README.)"""
    name = "payload"

    def fit(self, texts, labels):
        self.vec = TfidfVectorizer(analyzer="char", ngram_range=(2, 5), lowercase=True,
                                   min_df=2, sublinear_tf=True, max_features=60000)
        X = self.vec.fit_transform(texts)
        self.clf = LogisticRegression(max_iter=2000, C=8, class_weight="balanced").fit(X, labels)
        self.classes = list(self.clf.classes_)
        self.normal_idx = self.classes.index("normal")
        self.features = self.vec.get_feature_names_out()
        return self

    def _tokens(self, X, k, text, limit=4):
        row = X.tocoo()
        contrib = row.data * self.clf.coef_[k][row.col]
        low, toks = text.lower(), []
        for o in np.argsort(-contrib)[:10]:
            if contrib[o] <= 0:
                break
            pos = low.find(self.features[row.col[o]])
            if pos < 0:
                continue
            a, b = pos, pos + len(self.features[row.col[o]])
            while a > 0 and not low[a - 1].isspace():
                a -= 1
            while b < len(low) and not low[b].isspace():
                b += 1
            tok = text[a:b][:40]
            if tok and tok not in toks:
                toks.append(tok)
            if len(toks) >= limit:
                break
        return toks

    def analyze(self, req):
        text = normalize_text((req.get("query") or "") + " " + (req.get("body") or "")).strip()
        if not text:
            return AgentResult(self.name, 0.0, 0.3, {"attack_type": "normal", "tokens": [], "reason": ""})
        X = self.vec.transform([text])
        p = self.clf.predict_proba(X)[0]
        score = 1.0 - p[self.normal_idx]
        # little text to read => less sure
        length_factor = min(1.0, 0.3 + len(text) / 30)
        if score >= 0.5:
            masked = p.copy()
            masked[self.normal_idx] = -1
            k = int(np.argmax(masked))
            atype = self.classes[k]
            tokens = self._tokens(X, k, text)
            conf = min(1.0, float(score) * length_factor + 0.15 * (score > 0.8))
            reason = f"Payload looks like {atype} ({score * 100:.0f}% sure)."
            if tokens:
                reason += " Suspicious parts: " + ", ".join(f"`{t}`" for t in tokens) + "."
            return AgentResult(self.name, float(score), float(conf),
                               {"attack_type": atype, "tokens": tokens, "reason": reason})
        conf = float(p[self.normal_idx]) * length_factor
        return AgentResult(self.name, float(score), conf, {"attack_type": "normal", "tokens": [],
                                                           "reason": ""})


# ------------------------------------------------------------------ Agent 3
class BehaviorAgent:
    """Learns which endpoint follows which in normal sessions (a Markov sequence model).
    Unusual jumps (e.g. /login -> /admin) and request bursts score high.
    (Lightweight stand-in for the proposal's LSTM - see README.)"""
    name = "behavior"

    def fit(self, sequences, alpha=0.2):
        self.alpha = alpha
        self.counts = defaultdict(Counter)
        vocab = set()
        for seq in sequences:
            prev = "<start>"
            for ep in seq:
                self.counts[prev][ep] += 1
                vocab.add(ep)
                prev = ep
        self.vocab = vocab
        self.V = len(vocab) + 1
        return self

    def _nll(self, prev, nxt):
        c = self.counts.get(prev, {})
        tot = sum(c.values())
        if nxt not in self.vocab:
            return 8.0, 0.0                      # endpoint never seen in normal traffic
        if prev != "<start>" and prev not in self.vocab:
            return 6.0, 0.0                      # coming from an endpoint never seen in normal traffic
        p = (c.get(nxt, 0) + self.alpha) / (tot + self.alpha * self.V)
        return -math.log(p), c.get(nxt, 0) / tot if tot else 0.0

    def analyze(self, history, rate):
        """history: endpoints of this user's session, newest last. rate: requests in last 10s."""
        seq = ["<start>"] + list(history[-5:])
        steps = [self._nll(seq[i], seq[i + 1]) + (seq[i], seq[i + 1]) for i in range(len(seq) - 1)]
        nlls = [s[0] for s in steps]
        last, avg = nlls[-1], sum(nlls) / len(nlls)
        s_seq = _sigmoid(1.2 * (0.6 * last + 0.4 * avg - 4.5))
        s_rate = min(1.0, max(0.0, (rate - 8) / 10))
        score = max(s_seq, s_rate)
        conf = min(1.0, 0.25 + 0.15 * len(history))
        if s_seq >= 0.9:
            conf = max(conf, 0.8)                # a never-seen step is strong evidence
        reasons = []
        if s_seq >= 0.5:
            prev, nxt = steps[-1][2], steps[-1][3]
            seen = steps[-1][1] * 100
            reasons.append(f"Unusual step {prev if prev != '<start>' else '(session start)'} -> {nxt}; "
                           f"only {seen:.1f}% of normal sessions do this")
        if s_rate >= 0.3:
            reasons.append(f"{rate} requests in the last 10 seconds (burst)")
        reason = "Behavior is unusual: " + "; ".join(reasons) + "." if reasons else ""
        return AgentResult(self.name, float(score), float(conf), {"reason": reason, "rate": rate})
