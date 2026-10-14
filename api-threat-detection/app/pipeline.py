"""The full request pipeline: session -> fast filter -> 3 agents (parallel) -> vote -> explain -> log."""
import hashlib
import json
import logging
import re
import sqlite3
import threading
import time
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, wait

from .config import load_config
from .decision import AGENT_NAMES, WeightManager, aggregate, explain, verdict_for
from .traffic import KNOWN_ENDPOINTS, normalize_text

TOOL_RE = re.compile(r"sqlmap|nikto|nmap|masscan|python-requests|curl|wget|dirbuster|gobuster|scanner", re.I)
BAD_CHARS = set("'<>;|`$()\\")
BAD_WORDS = re.compile(r"\b(select|union|insert|drop|delete|update|exec|script|alert|onerror|onload|"
                       r"onfocus|eval|passwd|shadow|wget|curl|whoami|sleep|javascript|iframe)\b", re.I)
BAD_PATTERNS = re.compile(r"\.\./|\.\.\\|/etc/|%00|--|/\*|\bor\b\s*['\d]", re.I)
RATE_WINDOW = 10.0
log = logging.getLogger("pipeline")


class SessionStore:
    """Per-user history (stands in for the Redis session cache)."""

    def __init__(self, max_users=5000):
        self.data, self.max_users, self.lock = OrderedDict(), max_users, threading.Lock()

    def add(self, key, ts, endpoint):
        with self.lock:
            dq = self.data.pop(key, None) or deque(maxlen=60)
            dq.append((ts, endpoint))
            self.data[key] = dq
            if len(self.data) > self.max_users:
                self.data.popitem(last=False)
            rate = sum(1 for t, _ in dq if t >= ts - RATE_WINDOW)
            return [e for _, e in dq], rate


class FastFilter:
    """Cheap rule check. Anything that looks clean skips the AI agents."""

    def __init__(self, rate_threshold=8, max_payload_chars=400):
        self.rate_threshold, self.max_payload_chars = rate_threshold, max_payload_chars
        self.clean_cache = OrderedDict()   # stands in for the Redis decision cache

    def _payload_ok(self, req):
        key = hashlib.sha1(f"{req['method']}|{req['endpoint']}|{req.get('query')}|{req.get('body')}".encode()).hexdigest()
        if key in self.clean_cache:
            return self.clean_cache[key], True
        text = normalize_text((req.get("query") or "") + " " + (req.get("body") or ""))
        reasons = []
        if any(c in BAD_CHARS for c in text):
            reasons.append("contains special characters used in attacks")
        if BAD_WORDS.search(text):
            reasons.append("contains attack-related keywords")
        if BAD_PATTERNS.search(text):
            reasons.append("matches a known attack pattern")
        if len(text) > self.max_payload_chars:
            reasons.append("payload is unusually long")
        if not reasons:
            self.clean_cache[key] = []
            if len(self.clean_cache) > 5000:
                self.clean_cache.popitem(last=False)
        return reasons, False

    def check(self, req, rate):
        reasons = []
        if req["endpoint"] not in KNOWN_ENDPOINTS:
            reasons.append(f"endpoint {req['endpoint']} is not one the API normally serves")
        ua = (req.get("headers") or {}).get("User-Agent", "")
        if not ua:
            reasons.append("no User-Agent header")
        elif TOOL_RE.search(ua):
            reasons.append("User-Agent looks like a hacking or scripting tool")
        if rate > self.rate_threshold:
            reasons.append(f"{rate} requests in 10 seconds")
        p_reasons, cached = self._payload_ok(req)
        reasons += p_reasons
        return bool(reasons), reasons, cached


DECISION_COLS = ["id", "ts", "ip", "user", "method", "path", "payload", "route", "score", "verdict",
                 "attack_type", "explanation", "agents", "latency_ms", "label", "override",
                 "mode", "degraded", "thresholds", "request_id", "identity_source"]


class Pipeline:
    def __init__(self, agents, db_path, cfg=None, update_every=None):
        self.cfg = cfg or load_config()
        if update_every is not None:                      # old call style: Pipeline(agents, db, update_every=100)
            self.cfg["weights"]["update_every"] = update_every
        self.anomaly, self.payload, self.behavior = agents
        self.agent_objs = {"anomaly": self.anomaly, "payload": self.payload, "behavior": self.behavior}
        ff = self.cfg["fast_filter"]
        self.sessions = SessionStore()
        self.fast = FastFilter(ff["rate_threshold"], ff["max_payload_chars"])
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self.weights = WeightManager(self.cfg["weights"], on_update=self._save_weight_update)
        saved = self._load_weights()
        if saved:
            self.weights.reset(saved)
        self.pool = ThreadPoolExecutor(max_workers=3)
        row = self.db.execute("SELECT COALESCE(MAX(id),0) FROM decisions").fetchone()
        self.next_id = row[0] + 1
        self.reset_memory()

    # ---------------------------------------------------------------- storage
    def _init_db(self):
        with self.lock:
            self.db.execute("""CREATE TABLE IF NOT EXISTS decisions (
                id INTEGER PRIMARY KEY, ts REAL, ip TEXT, user TEXT, method TEXT, path TEXT, payload TEXT,
                route TEXT, score REAL, verdict TEXT, attack_type TEXT, explanation TEXT, agents TEXT,
                latency_ms REAL, label INTEGER, override TEXT, mode TEXT, degraded INTEGER, thresholds TEXT,
                request_id TEXT, identity_source TEXT, override_by TEXT)""")
            have = {r[1] for r in self.db.execute("PRAGMA table_info(decisions)")}
            for col, typ in (("mode", "TEXT"), ("degraded", "INTEGER"), ("thresholds", "TEXT"),
                             ("request_id", "TEXT"), ("identity_source", "TEXT"), ("override_by", "TEXT")):
                if col not in have:                       # upgrade an audit.db made by the old prototype
                    self.db.execute(f"ALTER TABLE decisions ADD COLUMN {col} {typ}")
            self.db.execute("""CREATE TABLE IF NOT EXISTS weight_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, skipped INTEGER, old TEXT, new TEXT,
                mcc TEXT, window INTEGER, positives INTEGER, provenance TEXT, reason TEXT)""")
            self.db.commit()

    def _save_weight_update(self, e):
        with self.lock:
            self.db.execute("INSERT INTO weight_updates (ts, skipped, old, new, mcc, window, positives, provenance, reason) "
                            "VALUES (?,?,?,?,?,?,?,?,?)",
                            (e["ts"], int(e["skipped"]), json.dumps(e["old"]), json.dumps(e["new"]),
                             json.dumps(e.get("mcc")), e["window"], e["positives"], json.dumps(e["provenance"]),
                             e.get("reason")))
            self.db.commit()

    def _load_weights(self):
        row = self.db.execute("SELECT new FROM weight_updates WHERE skipped = 0 ORDER BY id DESC LIMIT 1").fetchone()
        if not row:
            return None
        w = json.loads(row[0])
        return w if set(w) >= set(AGENT_NAMES) else None

    def reset_memory(self):
        with self.lock:
            self.recent = OrderedDict()
            self.counters = {"total": 0, "fast": 0, "ai": 0, "ALLOW": 0, "FLAG": 0, "BLOCK": 0,
                             "degraded": 0, "failure_policy": 0}
            self.agent_errors = Counter()      # (agent, "timeout"|"error") -> count
            self.latencies = deque(maxlen=120)
            self.ai_latencies = deque(maxlen=500)

    def reset_all(self):
        with self.lock:
            self.db.execute("DELETE FROM decisions")
            self.db.execute("DELETE FROM weight_updates")
            self.db.commit()
        self.reset_memory()
        self.weights.reset()
        self.sessions = SessionStore()

    # ---------------------------------------------------------------- core
    def run_agents(self, req, history, rate, disabled=None, timeout_s=None):
        """Run the enabled agents in parallel with one shared deadline (FR-031, FR-033, FR-034).
        Returns (results, excluded) where excluded maps agent -> reason."""
        disabled = set(self.cfg["agents"]["disabled"] if disabled is None else disabled)
        timeout_s = self.cfg["agents"]["timeout_ms"] / 1000 if timeout_s is None else timeout_s
        calls = {"anomaly": (self.anomaly.analyze, (req,)), "payload": (self.payload.analyze, (req,)),
                 "behavior": (self.behavior.analyze, (history, rate))}
        futures, excluded = {}, {}
        for n, (fn, args) in calls.items():
            if n in disabled:
                excluded[n] = "disabled in configuration"
            else:
                futures[n] = self.pool.submit(fn, *args)
        wait(list(futures.values()), timeout=timeout_s)
        results = {}
        for n, fut in futures.items():
            if not fut.done():
                fut.cancel()
                excluded[n] = f"timed out after {timeout_s * 1000:.0f} ms"
                self.agent_errors[(n, "timeout")] += 1
                continue
            try:
                r = fut.result()
                if not (0.0 <= r.score <= 1.0 and 0.0 <= r.confidence <= 1.0):
                    raise ValueError(f"out-of-range output score={r.score} confidence={r.confidence}")
                results[n] = r
            except Exception as e:     # AI-009: a broken agent is excluded, never trusted
                excluded[n] = f"error: {type(e).__name__}"
                self.agent_errors[(n, "error")] += 1
        return results, excluded

    def process(self, req, force_ai=False, log=True, learn=False, mode=None, disabled=None):
        """mode / disabled override config.json for one call (used by evaluate.py ablations)."""
        t0 = time.perf_counter()
        t1, t2 = self.cfg["thresholds"]["allow_below"], self.cfg["thresholds"]["block_above"]
        history, rate = self.sessions.add(req.get("user") or req.get("ip"), req["ts"], req["endpoint"])
        suspicious, fast_reasons, cached = self.fast.check(req, rate)
        weights = dict(self.weights.weights)
        rec = {"mode": None, "excluded": {}, "degraded": False, "policy_used": None, "thresholds": [t1, t2],
               "request_id": req.get("request_id"), "identity_source": req.get("identity_source"),
               "ts": req["ts"], "ip": req.get("ip", ""), "user": req.get("user", ""),
               "method": req["method"], "path": req["path"],
               "payload": ((req.get("query") or "") + " " + (req.get("body") or "")).strip()[:300],
               "label": req.get("label"), "fast_suspicious": suspicious,
               "fast_reasons": fast_reasons, "override": None}
        if not suspicious and not force_ai:
            rec.update(route="fast", score=0.0, verdict="ALLOW", agents={}, weights=weights,
                       explanation={"summary": "Allowed by the fast filter in a few milliseconds. No AI needed.",
                                    "evidence": ["Known endpoint, clean payload, normal request rate."]
                                    + (["Decision came from the cache."] if cached else []),
                                    "action": "No action needed.", "attack_type": "normal", "lead_agent": None})
            results = None
        else:
            results, excluded = self.run_agents(req, history, rate, disabled=disabled)
            agg_cfg = self.cfg["aggregation"]
            mode = mode or agg_cfg["mode"]
            agg = aggregate(results, weights, mode, agg_cfg["vote_threshold"], agg_cfg["epsilon"])
            policy_used = None
            if agg.score is None:              # no agent answered, or insufficient evidence (FR-036, AI-040)
                policy_used = self.cfg["agents"]["failure_policy"]
                verdict = "FLAG" if policy_used == "fail_open_flag" else "BLOCK"
                final = None
            else:
                final = agg.score
                verdict = verdict_for(final, t1, t2)
            expl = explain(results, weights, final, verdict, fast_reasons, agg=agg, excluded=excluded,
                           thresholds=(t1, t2), policy_used=policy_used)
            rec.update(route="ai", score=None if final is None else round(final, 4), verdict=verdict,
                       explanation=expl, weights=weights, mode=mode, excluded=excluded,
                       degraded=bool(excluded), policy_used=policy_used,
                       agents={n: {"score": round(r.score, 3), "confidence": round(r.confidence, 3),
                                   "weight": round(weights[n], 3),
                                   "contribution": round(agg.contributions.get(n, 0.0), 4),
                                   "reason": r.detail.get("reason", "")}
                               for n, r in results.items()})
        rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        rec["results"] = results            # kept for the evaluator; stripped before sending to the UI
        rec["attack_type"] = rec["explanation"]["attack_type"]
        if not log:
            return rec
        with self.lock:
            rec["id"] = self.next_id
            self.next_id += 1
            c = self.counters
            c["total"] += 1
            c["fast" if rec["route"] == "fast" else "ai"] += 1
            c[rec["verdict"]] += 1
            c["degraded"] += bool(rec["degraded"])
            c["failure_policy"] += bool(rec["policy_used"])
            self.latencies.append((rec["route"], rec["latency_ms"]))
            if rec["route"] == "ai":
                self.ai_latencies.append(rec["latency_ms"])
            self.recent[rec["id"]] = rec
            while len(self.recent) > 1500:
                self.recent.popitem(last=False)
        rec["results"] = None
        if learn and rec["label"] is not None and rec["route"] == "ai" and rec["agents"]:
            self.weights.feedback({n: a["score"] for n, a in rec["agents"].items()}, rec["label"], "corpus")
        self._save(rec)
        return rec

    def record_rate_limited(self, req, count, limit, window_s):
        """FR-028: a request over the gateway rate limit gets 429 and still leaves a decision record."""
        rec = {"ts": req["ts"], "ip": req.get("ip", ""), "user": req.get("user", ""), "method": req["method"],
               "path": req["path"], "payload": ((req.get("query") or "") + " " + (req.get("body") or "")).strip()[:300],
               "route": "rate_limit", "score": None, "verdict": "BLOCK", "attack_type": "rate_abuse",
               "agents": {}, "latency_ms": 0.0, "label": req.get("label"), "override": None, "mode": None,
               "degraded": False, "excluded": {}, "policy_used": None, "fast_reasons": [],
               "thresholds": [self.cfg["thresholds"]["allow_below"], self.cfg["thresholds"]["block_above"]],
               "request_id": req.get("request_id"), "identity_source": req.get("identity_source"),
               "explanation": {"summary": f"Rejected by the gateway rate limit: {count} requests in {window_s:g} s "
                                          f"(limit {limit}). Not analysed by the agents.",
                               "evidence": [f"{count} requests from this identity in the last {window_s:g} seconds."],
                               "action": "Check whether this client is a script or a scraper.",
                               "attack_type": "rate_abuse", "lead_agent": None}}
        with self.lock:
            rec["id"] = self.next_id
            self.next_id += 1
            self.counters["total"] += 1
            self.counters["BLOCK"] += 1
            self.counters["rate_limited"] = self.counters.get("rate_limited", 0) + 1
            self.recent[rec["id"]] = rec
        self._save(rec)
        return rec

    def _save(self, r):
        """FR-064 / NFR-017: a failed write is logged and counted; it never stops enforcement."""
        try:
            self._insert(r)
        except Exception as e:
            with self.lock:
                self.counters["write_failures"] = self.counters.get("write_failures", 0) + 1
            log.error("audit write failed for decision %s: %s", r.get("id"), type(e).__name__)

    def _insert(self, r):
        with self.lock:
            self.db.execute(f"INSERT INTO decisions ({','.join(DECISION_COLS)}) VALUES ({','.join('?' * len(DECISION_COLS))})",
                            (r["id"], r["ts"], r["ip"], r["user"], r["method"], r["path"], r["payload"], r["route"],
                             r["score"], r["verdict"], r["attack_type"], json.dumps(r["explanation"]),
                             json.dumps(r["agents"]), r["latency_ms"], r["label"], r["override"],
                             r["mode"], int(bool(r["degraded"])), json.dumps(r["thresholds"]),
                             r.get("request_id"), r.get("identity_source")))
            self.db.commit()

    # ---------------------------------------------------------------- analyst
    def override(self, rec_id, action, analyst=None):
        with self.lock:
            rec = self.recent.get(rec_id)
            if not rec or action not in ("allow", "block"):
                return None
            rec["override"] = action
            rec["override_by"] = analyst
            self.db.execute("UPDATE decisions SET override=?, override_by=? WHERE id=?", (action, analyst, rec_id))
            self.db.commit()
        if rec["agents"]:
            self.weights.feedback({n: a["score"] for n, a in rec["agents"].items()},
                                  1 if action == "block" else 0, "analyst")
        return rec

    # ---------------------------------------------------------------- stats
    @staticmethod
    def public(rec):
        keys = ["id", "ts", "ip", "user", "method", "path", "payload", "route", "score", "verdict",
                "attack_type", "explanation", "agents", "latency_ms", "label", "override", "fast_reasons",
                "mode", "degraded", "excluded", "policy_used", "thresholds", "request_id", "identity_source", "override_by"]
        return {k: rec.get(k) for k in keys}

    def stats(self):
        with self.lock:
            recs = list(self.recent.values())
            c = dict(self.counters)
            lat = list(self.latencies)
            ai = sorted(self.ai_latencies)
        types = {}
        for r in recs:
            if r["verdict"] != "ALLOW":
                types[r["attack_type"]] = types.get(r["attack_type"], 0) + 1
        fast_lat = [l for k, l in lat if k == "fast"]
        queue = [self.public(r) for r in reversed(recs) if r["verdict"] == "FLAG" and not r["override"]][:12]
        try:
            self.db.execute("SELECT 1").fetchone()
            db_ok = True
        except Exception:
            db_ok = False
        return {
            "counters": c,
            "fast_share": round(c["fast"] / c["total"] * 100, 1) if c["total"] else 0,
            "avg_fast_ms": round(sum(fast_lat) / len(fast_lat), 2) if fast_lat else 0,
            "avg_ai_ms": round(sum(ai) / len(ai), 1) if ai else 0,
            "p95_ai_ms": round(ai[int(len(ai) * 0.95) - 1], 1) if len(ai) >= 20 else (ai[-1] if ai else 0),
            "latency_series": [round(l, 2) for _, l in lat[-80:]],
            "attack_types": types,
            "agents": self.weights.snapshot(),
            "queue": queue,
            "recent": [self.public(r) for r in reversed(recs)][:30],
            "health": {"gateway": True, "fast_filter": True,
                       **{n: n not in self.cfg["agents"]["disabled"] for n in AGENT_NAMES},
                       "decision_engine": True, "xai": True, "database": db_ok},
            "agent_errors": {f"{n}_{k}": v for (n, k), v in self.agent_errors.items()},
            "settings": {"mode": self.cfg["aggregation"]["mode"], "thresholds": [
                self.cfg["thresholds"]["allow_below"], self.cfg["thresholds"]["block_above"]],
                "failure_policy": self.cfg["agents"]["failure_policy"],
                "timeout_ms": self.cfg["agents"]["timeout_ms"]},
        }
