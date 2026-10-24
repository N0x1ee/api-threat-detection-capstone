"""The full request pipeline: session -> fast filter -> 3 agents (parallel) -> vote -> explain -> log."""
import hashlib
import json
import logging
import os
import queue
import sqlite3
import threading
import time
from collections import Counter, OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor, wait

from .config import load_config
from .decision import AGENT_NAMES, WeightManager, aggregate, explain, verdict_for
from .fastfilter import FastFilter, load_rules

RATE_WINDOW = 10.0
log = logging.getLogger("pipeline")


class SessionStore:
    """Per-user history (stands in for the Redis session cache)."""

    def __init__(self, max_users=5000):
        self.data, self.max_users, self.lock = OrderedDict(), max_users, threading.Lock()

    def add(self, key, ts, endpoint, method=None, auth=None):
        with self.lock:
            dq = self.data.pop(key, None) or deque(maxlen=60)
            dq.append((ts, endpoint, method, auth))
            self.data[key] = dq
            if len(self.data) > self.max_users:
                self.data.popitem(last=False)
            rate = sum(1 for x in dq if x[0] >= ts - RATE_WINDOW)
            return [x[1] for x in dq], rate

    def events(self, key):
        """Event dicts for the LSTM behaviour agent (status is not known in-process)."""
        with self.lock:
            return [{"e": e, "m": m, "s": None, "t": t, "a": a} for t, e, m, a in self.data.get(key, ())]


DECISION_COLS = ["id", "ts", "ip", "user", "method", "path", "payload", "route", "score", "verdict",
                 "attack_type", "explanation", "agents", "latency_ms", "label", "override",
                 "mode", "degraded", "thresholds", "request_id", "identity_source",
                 "timings", "rule_ids", "rules_version", "cache_hit"]
EXTRA_COLS = (("mode", "TEXT"), ("degraded", "INTEGER"), ("thresholds", "TEXT"), ("request_id", "TEXT"),
              ("identity_source", "TEXT"), ("override_by", "TEXT"), ("timings", "TEXT"), ("rule_ids", "TEXT"),
              ("rules_version", "TEXT"), ("cache_hit", "INTEGER"))
ADJ_OUTCOMES = ("malicious", "benign", "undetermined")


class Pipeline:
    def __init__(self, agents, db_path, cfg=None, update_every=None):
        self.cfg = cfg or load_config()
        if update_every is not None:                      # old call style: Pipeline(agents, db, update_every=100)
            self.cfg["weights"]["update_every"] = update_every
        self.anomaly, self.payload, self.behavior = agents
        self.agent_objs = {"anomaly": self.anomaly, "payload": self.payload, "behavior": self.behavior}
        ff = self.cfg["fast_filter"]
        self.sessions = SessionStore()
        rules_path = ff.get("rules_file") or None
        if rules_path and not os.path.isabs(rules_path):
            rules_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), rules_path)
        self.fast = FastFilter(load_rules(rules_path), ff["rate_threshold"], ff["rate_window_s"],
                               ff["max_payload_chars"], ff.get("cache_ttl_s", 60))
        self.lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self.weights = WeightManager(self.cfg["weights"], on_update=self._save_weight_update)
        saved = self._load_weights()
        if saved:
            self.weights.reset(saved)
        self.pool = ThreadPoolExecutor(max_workers=3)
        # FR-056 / ADD-17: audit records are written by a background thread, off the request path
        self.write_queue = queue.Queue(maxsize=self.cfg.get("audit", {}).get("queue_size", 10000))
        self.async_writes = bool(self.cfg.get("audit", {}).get("async_writes", True))
        if self.async_writes:
            threading.Thread(target=self._writer_loop, daemon=True, name="audit-writer").start()
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
                request_id TEXT, identity_source TEXT, override_by TEXT, timings TEXT, rule_ids TEXT,
                rules_version TEXT, cache_hit INTEGER)""")
            have = {r[1] for r in self.db.execute("PRAGMA table_info(decisions)")}
            for col, typ in EXTRA_COLS:
                if col not in have:                       # upgrade an audit.db made by the old prototype
                    self.db.execute(f"ALTER TABLE decisions ADD COLUMN {col} {typ}")
            self.db.execute("""CREATE TABLE IF NOT EXISTS weight_updates (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, skipped INTEGER, old TEXT, new TEXT,
                mcc TEXT, window INTEGER, positives INTEGER, provenance TEXT, reason TEXT)""")
            # FR-079..084: analyst verdicts are linked records; the decision row is never changed (FR-082, NFR-037)
            self.db.execute("""CREATE TABLE IF NOT EXISTS adjudications (
                id INTEGER PRIMARY KEY AUTOINCREMENT, decision_id INTEGER NOT NULL, ts REAL, analyst TEXT,
                outcome TEXT NOT NULL, corrected_verdict TEXT, justification TEXT NOT NULL,
                seconds_in_queue REAL, original_verdict TEXT)""")
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
        self.flush()
        with self.lock:
            self.db.execute("DELETE FROM decisions")
            self.db.execute("DELETE FROM weight_updates")
            self.db.execute("DELETE FROM adjudications")
            self.db.commit()
        self.reset_memory()
        self.weights.reset()
        self.sessions = SessionStore()

    # ---------------------------------------------------------------- core
    @staticmethod
    def _timed(fn, *args):
        t = time.perf_counter()
        out = fn(*args)
        return out, (time.perf_counter() - t) * 1000

    def run_agents(self, req, history, rate, disabled=None, timeout_s=None):
        """Run the enabled agents in parallel with one shared deadline (FR-031, FR-033, FR-034, FR-038).
        Returns (results, excluded, agent_ms) where excluded maps agent -> reason."""
        disabled = set(self.cfg["agents"]["disabled"] if disabled is None else disabled)
        timeout_s = self.cfg["agents"]["timeout_ms"] / 1000 if timeout_s is None else timeout_s
        calls = {"anomaly": (self.anomaly.analyze, (req,)), "payload": (self.payload.analyze, (req,)),
                 "behavior": (self.behavior.analyze, (history, rate))}
        futures, excluded, agent_ms = {}, {}, {}
        for n, (fn, args) in calls.items():
            if n in disabled:
                excluded[n] = "disabled in configuration"
            else:
                futures[n] = self.pool.submit(self._timed, fn, *args)
        wait(list(futures.values()), timeout=timeout_s)
        results = {}
        for n, fut in futures.items():
            if not fut.done():
                fut.cancel()
                excluded[n] = f"timed out after {timeout_s * 1000:.0f} ms"
                self.agent_errors[(n, "timeout")] += 1
                continue
            try:
                r, ms = fut.result()
                agent_ms[n] = round(ms, 2)
                if not (0.0 <= r.score <= 1.0 and 0.0 <= r.confidence <= 1.0):
                    raise ValueError(f"out-of-range output score={r.score} confidence={r.confidence}")
                results[n] = r
            except Exception as e:     # AI-009: a broken agent is excluded, never trusted
                excluded[n] = f"error: {type(e).__name__}"
                self.agent_errors[(n, "error")] += 1
        return results, excluded, agent_ms

    def process(self, req, force_ai=False, log=True, learn=False, mode=None, disabled=None):
        """mode / disabled override config.json for one call (used by evaluate.py ablations)."""
        t0 = time.perf_counter()
        timings = {}                                       # FR-099: per-stage milliseconds
        t1, t2 = self.cfg["thresholds"]["allow_below"], self.cfg["thresholds"]["block_above"]
        skey = req.get("user") or req.get("ip")
        auth = bool({k.lower(): v for k, v in (req.get("headers") or {}).items()}.get("authorization"))
        history, rate = self.sessions.add(skey, req["ts"], req["endpoint"], req.get("method"), auth)
        if getattr(self.behavior, "model_name", "") == "lstm":
            history = self.sessions.events(skey)
        ts = time.perf_counter()
        suspicious, fast_reasons, rule_ids, cached = self.fast.check(req, rate)
        timings["fast_filter"] = round((time.perf_counter() - ts) * 1000, 3)
        weights = dict(self.weights.weights)
        rec = {"mode": None, "excluded": {}, "degraded": False, "policy_used": None, "thresholds": [t1, t2],
               "request_id": req.get("request_id"), "identity_source": req.get("identity_source"),
               "ts": req["ts"], "ip": req.get("ip", ""), "user": req.get("user", ""),
               "method": req["method"], "path": req["path"],
               "payload": ((req.get("query") or "") + " " + (req.get("body") or "")).strip()[:300],
               "label": req.get("label"), "fast_suspicious": suspicious,
               "fast_reasons": fast_reasons, "rule_ids": rule_ids, "rules_version": self.fast.version,
               "cache_hit": cached, "override": None, "adjudication": None}
        if not suspicious and not force_ai:
            rec.update(route="fast", score=0.0, verdict="ALLOW", agents={}, weights=weights,
                       explanation={"summary": "Allowed by the fast filter in a few milliseconds. No AI needed.",
                                    "evidence": [f"Passed all {len(self.fast.rules['rules'])} fast-filter rules "
                                                 f"(rules v{self.fast.version}): known endpoint, clean payload, "
                                                 "normal request rate."]
                                    + (["Payload already checked clean recently (decision cache)."] if cached else []),
                                    "action": "No action needed.", "attack_type": "normal", "lead_agent": None})
            results = None
        else:
            ts = time.perf_counter()
            results, excluded, agent_ms = self.run_agents(req, history, rate, disabled=disabled)
            timings["agents"] = round((time.perf_counter() - ts) * 1000, 3)
            timings["per_agent"] = agent_ms
            agg_cfg = self.cfg["aggregation"]
            mode = mode or agg_cfg["mode"]
            ts = time.perf_counter()
            agg = aggregate(results, weights, mode, agg_cfg["vote_threshold"], agg_cfg["epsilon"])
            policy_used = None
            if agg.score is None:              # no agent answered, or insufficient evidence (FR-036, AI-040)
                policy_used = self.cfg["agents"]["failure_policy"]
                verdict = "FLAG" if policy_used == "fail_open_flag" else "BLOCK"
                final = None
            else:
                final = agg.score
                verdict = verdict_for(final, t1, t2)
            timings["aggregation"] = round((time.perf_counter() - ts) * 1000, 3)
            ts = time.perf_counter()
            expl = explain(results, weights, final, verdict, fast_reasons, agg=agg, excluded=excluded,
                           thresholds=(t1, t2), policy_used=policy_used)
            timings["explanation"] = round((time.perf_counter() - ts) * 1000, 3)
            rec.update(route="ai", score=None if final is None else round(final, 4), verdict=verdict,
                       explanation=expl, weights=weights, mode=mode, excluded=excluded,
                       degraded=bool(excluded), policy_used=policy_used,
                       agents={n: {"score": round(r.score, 3), "confidence": round(r.confidence, 3),
                                   "weight": round(weights[n], 3),
                                   "contribution": round(agg.contributions.get(n, 0.0), 4),
                                   "reason": r.detail.get("reason", "")}
                               for n, r in results.items()})
        rec["latency_ms"] = round((time.perf_counter() - t0) * 1000, 2)
        timings["total"] = rec["latency_ms"]
        rec["timings"] = timings
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
               "timings": {}, "rule_ids": ["GATEWAY-RATE-LIMIT"], "rules_version": self.fast.version,
               "cache_hit": False, "adjudication": None,
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

    def _row(self, r):
        return (r["id"], r["ts"], r["ip"], r["user"], r["method"], r["path"], r["payload"], r["route"],
                r["score"], r["verdict"], r["attack_type"], json.dumps(r["explanation"]),
                json.dumps(r["agents"]), r["latency_ms"], r["label"], r["override"],
                r["mode"], int(bool(r["degraded"])), json.dumps(r["thresholds"]),
                r.get("request_id"), r.get("identity_source"), json.dumps(r.get("timings")),
                json.dumps(r.get("rule_ids") or []), r.get("rules_version"), int(bool(r.get("cache_hit"))))

    def _save(self, r):
        """Queue the record for the background writer (FR-056). Values are copied now, so later
        in-memory changes never alter what is written (NFR-037)."""
        row = self._row(r)
        if not self.async_writes:
            self._write(row)
            return
        try:
            self.write_queue.put_nowait(row)
        except queue.Full:                    # never block a client request on the audit path
            self._count_failure(row[0], "queue full")

    def _writer_loop(self):
        while True:
            row = self.write_queue.get()
            try:
                if row is None:                   # close() sentinel
                    return
                self._write(row)
            finally:
                self.write_queue.task_done()

    def close(self):
        """Write everything still queued, stop the writer thread, then close the database."""
        if getattr(self, "_closed", False):
            return
        self._closed = True
        self.flush()
        if self.async_writes:
            self.write_queue.put(None)
            self.flush()
        self.pool.shutdown(wait=False, cancel_futures=True)
        with self.lock:
            self.db.close()

    def _write(self, row):
        """FR-064 / NFR-017: a failed write is logged and counted; it never stops enforcement."""
        try:
            with self.lock:
                self.db.execute(f"INSERT INTO decisions ({','.join(DECISION_COLS)}) "
                                f"VALUES ({','.join('?' * len(DECISION_COLS))})", row)
                self.db.commit()
        except Exception as e:
            self._count_failure(row[0], type(e).__name__)

    def _count_failure(self, rec_id, why):
        with self.lock:
            self.counters["write_failures"] = self.counters.get("write_failures", 0) + 1
        log.error("audit write failed for decision %s: %s", rec_id, why)

    def flush(self, timeout=10.0):
        """Wait until every queued audit record is written (used by tests, evaluation and shutdown)."""
        if not self.async_writes:
            return True
        end = time.time() + timeout
        while self.write_queue.unfinished_tasks and time.time() < end:
            time.sleep(0.005)
        return not self.write_queue.unfinished_tasks

    # ---------------------------------------------------------------- analyst
    def adjudicate(self, rec_id, outcome, justification, analyst=None, corrected_verdict=None):
        """FR-079..084: record an analyst verdict as a separate, linked row. Returns (rec, error)."""
        outcome = (outcome or "").strip().lower()
        justification = (justification or "").strip()
        if outcome not in ADJ_OUTCOMES:
            return None, f"outcome must be one of {', '.join(ADJ_OUTCOMES)}"
        if corrected_verdict not in (None, "", "ALLOW", "FLAG", "BLOCK"):
            return None, "corrected_verdict must be ALLOW, FLAG or BLOCK"
        if len(justification) < 5:
            return None, "a justification of at least 5 characters is required"
        with self.lock:
            rec = self.recent.get(rec_id)
        if not rec:
            return None, "decision not found"
        now = time.time()
        adj = {"outcome": outcome, "justification": justification[:1000], "analyst": analyst,
               "corrected_verdict": corrected_verdict or None, "ts": now,
               "seconds_in_queue": round(max(0.0, now - rec["ts"]), 1), "original_verdict": rec["verdict"]}
        self.flush()
        with self.lock:
            self.db.execute("INSERT INTO adjudications (decision_id, ts, analyst, outcome, corrected_verdict, "
                            "justification, seconds_in_queue, original_verdict) VALUES (?,?,?,?,?,?,?,?)",
                            (rec_id, now, analyst, outcome, adj["corrected_verdict"], adj["justification"],
                             adj["seconds_in_queue"], rec["verdict"]))
            self.db.commit()
            rec["adjudication"] = adj
        if rec["agents"] and outcome != "undetermined":          # FR-083: a confirmed verdict is a label
            self.weights.feedback({n: a["score"] for n, a in rec["agents"].items()},
                                  1 if outcome == "malicious" else 0, "analyst")
        return rec, None

    def adjudications_for(self, rec_id):
        self.flush()
        rows = self.db.execute("SELECT ts, analyst, outcome, corrected_verdict, justification, seconds_in_queue "
                               "FROM adjudications WHERE decision_id = ? ORDER BY id", (rec_id,)).fetchall()
        return [{"ts": t, "analyst": a, "outcome": o, "corrected_verdict": c, "justification": j,
                 "seconds_in_queue": q} for t, a, o, c, j, q in rows]

    # ---------------------------------------------------------------- stats
    @staticmethod
    def public(rec):
        keys = ["id", "ts", "ip", "user", "method", "path", "payload", "route", "score", "verdict",
                "attack_type", "explanation", "agents", "latency_ms", "label", "override", "fast_reasons",
                "mode", "degraded", "excluded", "policy_used", "thresholds", "request_id", "identity_source",
                "timings", "rule_ids", "rules_version", "cache_hit", "adjudication"]
        return {k: rec.get(k) for k in keys}

    @staticmethod
    def _pcts(values):
        v = sorted(x for x in values if x is not None)
        if not v:
            return None
        at = lambda p: v[min(len(v) - 1, int(len(v) * p))]
        return {"p50": round(at(0.5), 3), "p95": round(at(0.95), 3), "p99": round(at(0.99), 3), "n": len(v)}

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
        queue = [self.public(r) for r in reversed(recs) if r["verdict"] == "FLAG" and not r.get("adjudication")][:12]
        stage = {}                                         # FR-099 / NFR-006: per-stage latency percentiles
        for key in ("fast_filter", "agents", "aggregation", "explanation", "total"):
            stage[key] = self._pcts([r.get("timings", {}).get(key) for r in recs if r.get("timings")])
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
            "stage_latency_ms": stage,
            "rules_version": self.fast.version,
            "audit_queue_depth": self.write_queue.unfinished_tasks if self.async_writes else 0,
            "settings": {"mode": self.cfg["aggregation"]["mode"], "thresholds": [
                self.cfg["thresholds"]["allow_below"], self.cfg["thresholds"]["block_above"]],
                "failure_policy": self.cfg["agents"]["failure_policy"],
                "timeout_ms": self.cfg["agents"]["timeout_ms"]},
        }
