"""Behaviour Agent, primary model: LSTM over an identity's last k events (SRS v1.1 AI-026 to AI-031).

Event = (endpoint, method, response status class, time since previous request bucket, authenticated).
Classes: benign, scanning, credential_stuffing, scraping.
Score = 1 - P(benign).  Confidence (ADD-25): c = h * p, h = min(1, events / 5), p = max softmax(logits / T).

Training (train_lstm.py) uses Keras; inference here is pure NumPy so the agent containers stay light.
This module also holds the session generator used to train it (DS-2, behaviour part).
"""
import math
import random

import numpy as np

from .agents import AgentResult
from .traffic import FLOWS, KNOWN_ENDPOINTS, normalize_endpoint

CLASSES = ["benign", "scanning", "credential_stuffing", "scraping"]
K = 20
ENDPOINTS = ["<pad>", "<unk>"] + sorted(KNOWN_ENDPOINTS)
EP_ID = {e: i for i, e in enumerate(ENDPOINTS)}
METHODS = ["<pad>", "GET", "POST", "PUT", "DELETE", "OTHER"]
STATUS = ["<pad>", "unknown", "2xx", "3xx", "4xx", "5xx"]
GAPS = [0.2, 1.0, 3.0, 10.0, 60.0]            # bucket edges in seconds; +1 bucket for first event / longer
N_GAP = len(GAPS) + 3                         # 0 pad, 1 first event, 2..7 buckets


# ------------------------------------------------------------------ encoding
def status_class(code):
    if code in (None, "", "unknown"):
        return "unknown"
    try:
        return f"{int(code) // 100}xx" if 200 <= int(code) < 600 else "unknown"
    except (TypeError, ValueError):
        return "unknown"


def gap_bucket(gap):
    if gap is None:
        return 1
    for i, edge in enumerate(GAPS):
        if gap < edge:
            return 2 + i
    return 2 + len(GAPS)


def as_events(history):
    """Accepts event dicts {e|endpoint, m, s, t, a} or plain endpoint strings (older history format)."""
    out = []
    for h in history:
        if isinstance(h, str):
            out.append({"e": h, "m": None, "s": None, "t": None, "a": None})
        elif isinstance(h, dict):
            out.append({"e": h.get("e") or h.get("endpoint") or "", "m": h.get("m") or h.get("method"),
                        "s": h.get("s", h.get("status")), "t": h.get("t", h.get("ts")), "a": h.get("a", h.get("auth"))})
    return out


def encode_events(history, k=K):
    """-> int array (len, 5): endpoint, method, status, gap bucket, auth (0 pad, 1 no/unknown, 2 yes)."""
    ev = as_events(history)[-k:]
    rows, prev_t = [], None
    for e in ev:
        ep = normalize_endpoint(e["e"] or "/")
        m = (e["m"] or "GET").upper()
        t = e["t"]
        gap = None if (prev_t is None or t is None) else max(0.0, float(t) - float(prev_t))
        prev_t = t if t is not None else prev_t
        rows.append([EP_ID.get(ep, 1), METHODS.index(m) if m in METHODS else 5,
                     STATUS.index(status_class(e["s"])), gap_bucket(gap), 2 if e["a"] else 1])
    return np.array(rows, dtype=np.int32).reshape(-1, 5)


# ------------------------------------------------------------------ session generator (training data)
UNKNOWN_PATHS = ["/admin", "/wp-admin", "/.env", "/backup", "/api/v1/debug", "/config", "/phpinfo",
                 "/server-status", "/console", "/old", "/test", "/api/internal", "/.git/config", "/actuator",
                 "/swagger.json", "/graphql", "/metrics", "/upload", "/install", "/db"]


def _ev(ep, m, s, t, a):
    return {"e": ep, "m": m, "s": s, "t": t, "a": a}


def _concrete(rng, ep):
    return ep.replace("{id}", str(rng.randint(1, 500)))


def benign_session(rng, t):
    out, auth = [], False
    flow = list(rng.choice(FLOWS))
    if rng.random() < 0.3:                                   # longer browsing sessions
        flow += [rng.choice(["/products", "/products/{id}", "/search", "/help"]) for _ in range(rng.randint(3, 12))]
    for ep in flow:
        t += rng.uniform(0.8, 12.0) if out else 0
        if ep == "/login":
            for _ in range(rng.choice([0, 0, 0, 1, 2])):       # mistyped passwords happen
                out.append(_ev(ep, "POST", 401, t, False))
                t += rng.uniform(2, 8)
            out.append(_ev(ep, "POST", 200, t, False))
            auth = True
            continue
        if ep == "/logout":
            out.append(_ev(ep, "POST", 200, t, auth))
            auth = False
            continue
        s = 404 if rng.random() < 0.03 else 200
        m = "POST" if ep in ("/feedback", "/checkout", "/cart") and rng.random() < 0.6 else "GET"
        out.append(_ev(_concrete(rng, ep), m, s, t, auth))
    return out


def scanning_session(rng, t):
    out = []
    for i in range(rng.randint(8, 40)):
        t += rng.uniform(0.02, 0.8) if out else 0
        if rng.random() < 0.7:
            ep, s = rng.choice(UNKNOWN_PATHS), rng.choice([404, 404, 404, 403, 401])
        else:
            ep, s = _concrete(rng, rng.choice(sorted(KNOWN_ENDPOINTS))), rng.choice([200, 401, 405])
        out.append(_ev(ep, rng.choice(["GET", "GET", "GET", "HEAD", "OPTIONS", "POST"]), s, t, False))
    return out


def stuffing_session(rng, t):
    out = []
    for i in range(rng.randint(6, 40)):
        t += rng.uniform(0.1, 2.5) if out else 0
        ok = rng.random() < 0.03
        out.append(_ev("/login", "POST", 200 if ok else 401, t, False))
        if ok and rng.random() < 0.5:                         # attacker checks the account it got into
            t += rng.uniform(0.2, 1.0)
            out.append(_ev("/profile", "GET", 200, t, True))
    return out


def scraping_session(rng, t):
    out, auth = [], rng.random() < 0.4
    pid = rng.randint(1, 200)
    gap = rng.uniform(0.15, 1.5)
    for i in range(rng.randint(10, 60)):
        t += gap * rng.uniform(0.85, 1.15) if out else 0     # machine-regular timing
        if rng.random() < 0.15:
            out.append(_ev("/products", "GET", 200, t, auth))
        else:
            pid += 1
            out.append(_ev(f"/products/{pid}", "GET", 404 if rng.random() < 0.05 else 200, t, auth))
    return out


GENERATORS = {"benign": benign_session, "scanning": scanning_session,
              "credential_stuffing": stuffing_session, "scraping": scraping_session}


def traffic_sessions(rng, n):
    """Sessions from app/traffic.py (the evaluation generator), status unknown, as (class, events)."""
    from .traffic import ATTACK_KINDS, generate_session
    out = []
    for _ in range(n):
        kind = rng.choices(["normal", "recon", "attack"], weights=[0.6, 0.15, 0.25])[0]
        reqs = generate_session(rng, rng.choice(ATTACK_KINDS) if kind == "attack" else kind, 1_700_000_000)
        ev = [{"e": r["endpoint"], "m": r["method"], "s": None, "t": r["ts"],
               "a": bool((r.get("headers") or {}).get("Authorization"))} for r in reqs]
        out.append(("scanning" if kind == "recon" else "benign", ev))   # payload attacks are the payload agent's job
    return out


def make_windows(rng, n_sessions, status_dropout=0.5, min_prefix=1, n_traffic=0):
    """Sessions -> (X windows, y labels, prefix lengths). Every prefix of a session is a sample:
    at scoring time the agent sees the history so far, never the future."""
    X, y, lens = [], [], []
    shares = {"benign": 0.55, "scanning": 0.15, "credential_stuffing": 0.15, "scraping": 0.15}
    sessions = []
    for _ in range(n_sessions):
        cls = rng.choices(list(shares), weights=list(shares.values()))[0]
        sessions.append((cls, GENERATORS[cls](rng, 1_700_000_000 + rng.uniform(0, 1e6))))
    sessions += traffic_sessions(rng, n_traffic)
    rng.shuffle(sessions)
    for cls, sess in sessions:
        if rng.random() < status_dropout:                     # status not always known at scoring time
            for e in sess:
                if rng.random() < 0.7:
                    e["s"] = None
        step = max(1, len(sess) // 8)                         # sample prefixes, not all of them
        for end in sorted(set(list(range(min_prefix, len(sess) + 1, step)) + [len(sess)])):
            X.append(encode_events(sess[:end]))
            y.append(CLASSES.index(cls))
            lens.append(min(end, K))
    return X, np.array(y), np.array(lens)


def pad(windows, k=K):
    out = np.zeros((len(windows), k, 5), dtype=np.int32)
    for i, w in enumerate(windows):
        if len(w):
            out[i, -len(w):] = w                              # left-pad: newest event last
    return out


# ------------------------------------------------------------------ NumPy inference agent
def _sig(x):
    return 1.0 / (1.0 + np.exp(-x))


def _softmax(z):
    z = z - z.max()
    e = np.exp(z)
    return e / e.sum()


class LSTMBehaviorAgent:
    name = "behavior"
    model_name = "lstm"

    def __init__(self, weights_path):
        w = np.load(weights_path, allow_pickle=False)
        self.embs = [w[f"emb{i}"] for i in range(5)]
        self.Wx, self.Wh, self.b = w["lstm_kernel"], w["lstm_recurrent"], w["lstm_bias"]
        self.d_w, self.d_b = w["dense_k"], w["dense_b"]
        self.T = float(w["temperature"])
        self.units = self.Wh.shape[0]

    def logits(self, events):
        X = encode_events(events)
        P = pad([X])[0]          # the model was trained on left-padded windows of K, so run all K steps
        h = np.zeros(self.units)
        c = np.zeros(self.units)
        u = self.units
        for row in P:                                         # Keras gate order: i, f, c, o
            x = np.concatenate([self.embs[j][row[j]] for j in range(5)])
            z = x @ self.Wx + h @ self.Wh + self.b
            i, f, g, o = _sig(z[:u]), _sig(z[u:2 * u]), np.tanh(z[2 * u:3 * u]), _sig(z[3 * u:])
            c = f * c + i * g
            h = o * np.tanh(c)
        return h @ self.d_w + self.d_b, X

    @staticmethod
    def drivers(X, rate):
        """Plain-language features behind the call (AI-030)."""
        n = len(X)
        if n == 0:
            return []
        out = []
        fails = int(np.sum(X[:, 2] == STATUS.index("4xx")))
        unk = int(np.sum(X[:, 0] == 1))
        logins = int(np.sum(X[:, 0] == EP_ID.get("/login", -1)))
        fast = int(np.sum(np.isin(X[:, 3], [2, 3])))
        if unk:
            out.append(f"{unk} of last {n} requests went to endpoints the API does not have")
        if fails >= 3:
            out.append(f"{fails} of last {n} requests were rejected (4xx)")
        if logins >= 3:
            out.append(f"{logins} login attempts in last {n} requests")
        if fast >= max(3, n // 2):
            out.append(f"{fast} requests came less than 1 s after the previous one")
        pages = int(np.sum(X[:, 0] == EP_ID.get("/products/{id}", -1)))
        if pages >= max(5, n // 2):
            out.append(f"{pages} of last {n} requests walked through product pages one after another")
        if n >= 5 and np.bincount(X[1:, 3]).max() >= 0.8 * (n - 1):
            out.append("timing between requests is machine-regular")
        if rate:
            out.append(f"{rate} requests in the last 10 s")
        return out

    def analyze(self, history, rate=0):
        events = as_events(history)
        if not events:
            return AgentResult(self.name, 0.0, 0.0, {"reason": "", "history_len": 0, "model": self.model_name})
        z, X = self.logits(events)
        p_raw, p = _softmax(z), _softmax(z / self.T)
        h = min(1.0, len(events[-K:]) / 5.0)                 # AI-028: short history -> lower confidence
        score = float(1.0 - p_raw[0])
        conf = float(h * p.max())
        cls = CLASSES[int(np.argmax(p_raw))]
        detail = {"model": self.model_name, "history_len": len(events), "pattern": cls,
                  "probs": {c: round(float(v), 4) for c, v in zip(CLASSES, p_raw)}, "rate": rate}
        if cls != "benign" and score >= 0.5:
            why = self.drivers(X, rate)
            detail["reason"] = (f"Behaviour looks like {cls.replace('_', ' ')} ({score * 100:.0f}% sure)"
                                + (": " + "; ".join(why) if why else "") + ".")
            detail["attack_type"] = {"scanning": "recon"}.get(cls, cls)
        else:
            detail["reason"] = ""
        return AgentResult(self.name, score, conf, detail)
