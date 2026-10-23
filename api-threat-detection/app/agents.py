"""The three specialised agents. Each returns: score (0-1 threat), confidence (0-1), detail."""
import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from .traffic import normalize_text

FEATURES = [
    # Size (6)
    "total_length", "payload_length", "query_length", "header_count",
    "mean_header_value_length", "max_header_value_length",
    # Characters (6)
    "payload_entropy", "query_entropy", "alpha_ratio", "digit_ratio", "special_char_ratio",
    "non_printable_count",
    # Structure (5)
    "path_depth", "query_param_count", "method_code", "content_type_code", "length_mismatch",
]                                                               # SRS v1.1 Table 5.2 (AI-070)

METHOD_CODES = {"GET": 0, "HEAD": 0, "OPTIONS": 1, "POST": 2, "PUT": 3, "PATCH": 3, "DELETE": 4}
CONTENT_TYPES = (("json", 1), ("x-www-form-urlencoded", 2), ("multipart", 3), ("xml", 4), ("text", 5))


@dataclass
class AgentResult:
    name: str
    score: float
    confidence: float
    detail: dict = field(default_factory=dict)


def _sigmoid(x):
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, x))))


def _entropy(s):
    n = len(s)
    if not n:
        return 0.0
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def _content_type_code(h):
    ct = ""
    for k, v in h.items():
        if k.lower() == "content-type":
            ct = str(v).lower()
    if not ct:
        return 0
    return next((code for key, code in CONTENT_TYPES if key in ct), 6)


def _length_mismatch(h, body):
    for k, v in h.items():
        if k.lower() == "content-length":
            try:
                return float(int(v) != len((body or "").encode("utf-8", "replace")))
            except (TypeError, ValueError):
                return 1.0                                      # unparsable length counts as mismatch
    return 0.0


# ------------------------------------------------------------------ Agent 1
def extract_features(req):
    """The 17 structural features of Table 5.2, in FEATURES order. Pure function of the request."""
    query, body = req.get("query") or "", req.get("body") or ""
    path = req.get("path") or req.get("endpoint") or "/"
    h = req.get("headers") or {}
    # Payload = path + query + body (SR-BH carries most attack strings in the path itself)
    payload = normalize_text(path.split("?")[0] + " " + query + " " + body).strip()
    q_dec = normalize_text(query)
    n = len(payload)
    vals = [len(str(v)) for v in h.values()]
    if n:
        alpha = sum(ch.isalpha() for ch in payload) / n
        digit = sum(ch.isdigit() for ch in payload) / n
        special = sum(1 for ch in payload if not ch.isalnum() and not ch.isspace()) / n
    else:
        alpha = digit = special = 0.0
    nonprint = sum(1 for ch in normalize_text(path) + query + body if not ch.isprintable() and ch not in "\r\n\t")
    total = len(req.get("method") or "") + len(path) + len(query) + len(body) + \
        sum(len(str(k)) + len(str(v)) for k, v in h.items())
    return [
        total, n, len(query), len(h),
        (sum(vals) / len(vals)) if vals else 0.0, max(vals) if vals else 0,
        _entropy(payload), _entropy(q_dec), alpha, digit, special, nonprint,
        len([p for p in path.split("?")[0].split("/") if p]),
        len([p for p in query.split("&") if p]) if query else 0,
        METHOD_CODES.get((req.get("method") or "GET").upper(), 5),
        _content_type_code(h), _length_mismatch(h, body),
    ]


def _c(n):
    """Average path length of an unsuccessful BST search (Liu et al., 2008)."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    big = n > 2
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    out[n == 2] = 1.0
    return out


class AnomalyAgent:
    """Isolation Forest trained on NORMAL traffic only (AI-015, AI-018).

    score      = sigmoid((raw - t) / k), raw = sklearn anomaly score; t, k fitted on benign
                 validation data (AI-016): t = 98th percentile, k = (p99.9 - p50) / 4.
    confidence = 1 - min(1, sigma / sigma_ref) (ADD-25): sigma is the standard deviation of
                 the per-tree anomaly scores for this request, sigma_ref the 95th percentile
                 of sigma on validation data. Trees agree -> high confidence, whatever the score.
    """
    name = "anomaly"
    feature_version = 3

    def __init__(self, n_estimators=100, top_k=5, random_state=42, confidence_mode="ref"):
        # confidence_mode "ref" = ADD-25 as written; "range" = sigma rescaled between its
        # 5th and 95th validation percentiles (proposed change, pending team decision)
        self.n_estimators, self.top_k, self.random_state = n_estimators, top_k, random_state
        self.confidence_mode = confidence_mode

    def fit(self, reqs, validation=None):
        X = np.array([extract_features(r) for r in reqs], dtype=float)
        self.mu = X.mean(0)
        self.sd = np.maximum(X.std(0), 1e-3)
        self.model = IsolationForest(n_estimators=self.n_estimators,
                                     random_state=self.random_state).fit(X)
        self._h = None
        self.calibrate(validation if validation else reqs)
        return self

    def calibrate(self, reqs):
        """Fit the score mapping and sigma_ref on benign validation requests."""
        X = np.array([extract_features(r) for r in reqs], dtype=float)
        raw = -self.model.score_samples(X)
        self.t = float(np.percentile(raw, 98))
        self.k = max(1e-3, float(np.percentile(raw, 99.9) - np.percentile(raw, 50)) / 4)
        spread = self.tree_scores(X).std(1)
        self.sigma_ref = max(1e-6, float(np.percentile(spread, 95)))
        self.sigma_lo = float(np.percentile(spread, 5))
        self.calibrated_on = len(X)
        return self

    def _node_heights(self):
        """Per tree, the path-length estimate h for every node: depth + c(samples in node)."""
        hs = []
        for tree in self.model.estimators_:
            t = tree.tree_
            depth = np.zeros(t.node_count)
            for i in range(t.node_count):                       # parents precede children
                for ch in (t.children_left[i], t.children_right[i]):
                    if ch != -1:
                        depth[ch] = depth[i] + 1
            hs.append(depth + _c(t.n_node_samples))
        self._h = hs
        self._norm = float(_c([self.model.max_samples_])[0])

    def confidence_from_spread(self, sigma):
        if getattr(self, "confidence_mode", "ref") == "range":
            span = max(1e-6, self.sigma_ref - self.sigma_lo)
            return float(1.0 - min(1.0, max(0.0, (sigma - self.sigma_lo) / span)))
        return float(1.0 - min(1.0, sigma / self.sigma_ref))

    def tree_scores(self, X):
        """Per-tree anomaly scores s_t = 2^(-h_t / c(psi)), shape (n_requests, n_trees).
        The mean of log2 over trees reproduces sklearn's score_samples exactly."""
        if getattr(self, "_h", None) is None:
            self._node_heights()
        X = np.asarray(X, dtype=np.float32)
        out = np.empty((X.shape[0], len(self._h)))
        for j, (tree, feats) in enumerate(zip(self.model.estimators_, self.model.estimators_features_)):
            out[:, j] = self._h[j][tree.tree_.apply(np.ascontiguousarray(X[:, feats]))]
        return 2.0 ** (-out / self._norm)

    def top_features(self, x, k=None):
        """AI-017 / OD-18: features ranked by |z| against the benign training mean."""
        z = (x - self.mu) / self.sd
        order = np.argsort(-np.abs(z))[: (k or self.top_k)]
        return [{"feature": FEATURES[i], "value": round(float(x[i]), 3),
                 "normal_mean": round(float(self.mu[i]), 3), "z": round(float(z[i]), 2)} for i in order]

    def analyze(self, req):
        x = np.array(extract_features(req), dtype=float)
        try:
            ts = self.tree_scores(x[None, :])[0]
            raw = float(2.0 ** np.log2(ts).mean())              # identical to -score_samples(x)
            sigma = float(ts.std())
            conf = self.confidence_from_spread(sigma)
        except Exception:                                       # AI-036: never default to max
            raw = float(-self.model.score_samples(x[None, :])[0])
            sigma, conf = None, 0.0
        score = _sigmoid((raw - self.t) / self.k)
        top = self.top_features(x)
        reason = ""
        if score >= 0.3:
            strong = [f for f in top if abs(f["z"]) >= 3][:3]
            parts = [f"{f['feature']} = {f['value']:g} ({f['z']:+.1f} sd from normal)" for f in strong]
            reason = ("Request shape is unusual: " + "; ".join(parts) + ".") if parts else \
                "Request shape is statistically unusual compared with normal traffic."
        return AgentResult(self.name, float(score), float(conf),
                           {"reason": reason, "raw": raw, "tree_spread": sigma,
                            "sigma_ref": self.sigma_ref, "top_features": top})


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
