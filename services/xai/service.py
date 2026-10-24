"""XAI Generator + Dashboard API (Python, PostgreSQL).

Consumer: `decisions` -> explanation (app/decision.explain) -> PostgreSQL `decisions` table.
          `weights.updates` -> `weight_updates` table.
API (for the React dashboard): login/logout, feed, decision detail, analyst review (publishes to
`labels` for the decision engine's adaptive weights), stats, weights, auth events.
"""
import json
import logging
import os
import sys
import threading
import time
from types import SimpleNamespace

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("APP_ROOT", os.path.join(HERE, "..", "..", "api-threat-detection"))
sys.path.insert(0, os.path.abspath(ROOT))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..")))

import psycopg  # noqa: E402
from flask import Flask, g, jsonify, request  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402
from psycopg.types.json import Jsonb  # noqa: E402

from app.auth import COOKIE_NAME, Auth, AuthError  # noqa: E402
from app.config import load_config  # noqa: E402
from app.decision import Aggregation, explain  # noqa: E402
from common.bus import make_bus  # noqa: E402

log = logging.getLogger("xai")
DB_URL = os.environ.get("DATABASE_URL", "postgresql://capstone@localhost:5432/threats")
PUBLIC = {"/login", "/health"}
ADMIN_ONLY = {"/api/auth/events", "/api/users"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


# ---------------------------------------------------------------- explanation
def build_explanation(d):
    """Explanation for one `decisions` message, built only from that message's values (XAI-001)."""
    req = d.get("request") or {}
    ff = req.get("fast_filter") or {}
    th = d.get("thresholds") or {}
    t1, t2 = th.get("allow_below", 0.3), th.get("block_above", 0.7)
    route = d.get("route", "ai")
    if route != "ai":
        why = {"fast_filter": "Cleared by the fast filter: no rule matched, so the AI agents were skipped.",
               "rate_limit": "Rejected by the gateway rate limit before any analysis (HTTP 429)."}.get(route, route)
        return {"summary": why, "evidence": ff.get("reasons") or [], "action": "No action needed.",
                "attack_type": "normal" if route == "fast_filter" else "rate_abuse", "lead_agent": None,
                "structured": {"route": route, "verdict": d.get("verdict"), "final_score": d.get("score")}}
    results = {n: SimpleNamespace(score=a["score"], confidence=a["confidence"], detail=a.get("detail") or {})
               for n, a in (d.get("agents") or {}).items()}
    weights = {n: a.get("weight", 1.0) for n, a in (d.get("agents") or {}).items()}
    agg = Aggregation(d.get("score"), d.get("mode") or "A", d.get("numerator") or 0.0,
                      d.get("denominator") or 0.0, d.get("contributions") or {}, list(results))
    return explain(results, weights, d.get("score"), d.get("verdict"), ff.get("reasons") or [], agg=agg,
                   excluded=d.get("excluded") or {}, thresholds=(t1, t2), policy_used=d.get("policy_used"))


class Store:
    def __init__(self, url=DB_URL):
        self.url = url
        self.conn = self._connect()
        with open(os.path.join(HERE, "schema.sql")) as f:
            self.conn.execute(f.read())
        self.lock = threading.Lock()

    def _connect(self):
        for i in range(30):
            try:
                return psycopg.connect(self.url, autocommit=True, row_factory=dict_row)
            except psycopg.OperationalError:
                if i == 29:
                    raise
                time.sleep(1)

    def q(self, sql, params=()):
        with self.lock:
            return self.conn.execute(sql, params).fetchall()

    def x(self, sql, params=()):
        with self.lock:
            self.conn.execute(sql, params)

    def save_decision(self, d):
        req = d.get("request") or {}
        ff = req.get("fast_filter") or {}
        ex = build_explanation(d)
        self.x("""INSERT INTO decisions (request_id, ts, route, verdict, score, attack_type, mode, degraded, policy_used,
                    method, path, query, ip, identity, identity_source, rule_ids, rules_version, agents, excluded,
                    thresholds, numerator, denominator, explanation, timings_ms)
                  VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                  ON CONFLICT (request_id) DO NOTHING""",
               (d["request_id"], d.get("ts") or time.time(), d.get("route", "ai"), d["verdict"], d.get("score"),
                ex.get("attack_type"), d.get("mode"), bool(d.get("degraded")), d.get("policy_used"),
                req.get("method"), req.get("path"), (req.get("query") or "")[:2000], req.get("ip"),
                req.get("identity"), req.get("identity_source"), Jsonb(ff.get("rule_ids") or []),
                ff.get("rules_version"), Jsonb(d.get("agents") or {}), Jsonb(d.get("excluded") or {}),
                Jsonb(d.get("thresholds") or {}), d.get("numerator"), d.get("denominator"), Jsonb(ex),
                Jsonb(d.get("timings_ms") or {})))

    def save_weight_update(self, e):
        self.x("INSERT INTO weight_updates (ts, skipped, entry) VALUES (%s,%s,%s)",
               (e.get("ts") or time.time(), bool(e.get("skipped")), Jsonb(e)))


# ---------------------------------------------------------------- consumer
def start_consumer(store, bus, stop=None):
    def on_msg(topic, msg):
        if topic == "decisions":
            store.save_decision(msg)
        elif topic == "weights.updates":
            store.save_weight_update(msg)
    return bus.subscribe(["decisions", "weights.updates"], "xai", on_msg, stop)


# ---------------------------------------------------------------- dashboard API
def create_app(store, bus, auth, cfg):
    app = Flask(__name__)

    @app.before_request
    def require_login():
        if request.path in PUBLIC:
            return None
        sess = auth.session(request.cookies.get(COOKIE_NAME))
        if not sess:
            return jsonify(error="login required"), 401
        g.session, g.user, g.role = sess, sess["user"], sess["role"]
        if request.method in STATE_CHANGING and not auth.csrf_ok(sess, request.headers.get("X-CSRF-Token")):
            return jsonify(error="missing or invalid CSRF token"), 403
        if request.path in ADMIN_ONLY and sess["role"] != "admin":
            return jsonify(error="admin only"), 403
        return None

    @app.errorhandler(Exception)
    def internal_error(e):                       # SEC-033
        code = getattr(e, "code", 500)
        if code == 500:
            log.exception("request failed")
        return jsonify(error="request failed" if code == 500 else str(e)), code

    @app.post("/login")
    def login():
        body = request.get_json(silent=True) or {}
        try:
            token, sess = auth.login(body.get("username"), body.get("password"), request.remote_addr or "")
        except AuthError as e:
            return jsonify(error=str(e)), (429 if "too many" in str(e) else 401)
        resp = jsonify(user=sess["user"], role=sess["role"], csrf=sess["csrf"])
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Strict",
                        secure=bool(cfg["auth"]["cookie_secure"]), path="/")
        return resp

    @app.post("/logout")
    def logout():
        auth.logout(request.cookies.get(COOKIE_NAME), request.remote_addr or "")
        resp = jsonify(ok=True)
        resp.delete_cookie(COOKIE_NAME, path="/", samesite="Strict")
        return resp

    @app.get("/api/me")
    def me():
        return jsonify(user=g.user, role=g.role, csrf=g.session["csrf"])

    @app.get("/api/decisions")
    def feed():
        limit = max(1, min(500, request.args.get("limit", 50, type=int)))
        verdict = request.args.get("verdict")
        sql = ("SELECT id, request_id, ts, route, verdict, score, attack_type, degraded, method, path, ip, "
               "explanation->>'summary' AS summary FROM decisions")
        params = []
        if verdict in ("ALLOW", "FLAG", "BLOCK"):
            sql += " WHERE verdict = %s"
            params.append(verdict)
        sql += " ORDER BY ts DESC LIMIT %s"
        params.append(limit)
        return jsonify(decisions=store.q(sql, params))

    @app.get("/api/decisions/<rid>")
    def detail(rid):
        rows = store.q("SELECT * FROM decisions WHERE request_id = %s", (rid,))
        if not rows:
            return jsonify(error="not found"), 404
        rows[0]["created_at"] = str(rows[0]["created_at"])
        return jsonify(decision=rows[0])

    @app.post("/api/decisions/<rid>/adjudicate")
    def adjudicate(rid):                         # FR-079..083
        b = request.get_json(silent=True) or {}
        outcome, just = b.get("outcome"), (b.get("justification") or "").strip()
        corrected = b.get("corrected_verdict")
        if outcome not in ("malicious", "benign", "undetermined"):
            return jsonify(error="outcome must be malicious, benign or undetermined"), 400
        if not just:
            return jsonify(error="justification is required"), 400
        if corrected not in (None, "ALLOW", "FLAG", "BLOCK"):
            return jsonify(error="corrected_verdict must be ALLOW, FLAG or BLOCK"), 400
        rows = store.q("SELECT agents FROM decisions WHERE request_id = %s", (rid,))
        if not rows:
            return jsonify(error="not found"), 404
        now = time.time()
        store.x("""INSERT INTO adjudications (request_id, ts, analyst, outcome, justification, corrected_verdict)
                   VALUES (%s,%s,%s,%s,%s,%s)""", (rid, now, g.user, outcome, just[:2000], corrected))
        scores = {n: a["score"] for n, a in (rows[0]["agents"] or {}).items()}
        if outcome != "undetermined" and scores:     # only definite outcomes train the weights
            bus.publish("labels", rid, {"request_id": rid, "label": int(outcome == "malicious"),
                                        "provenance": "analyst", "scores": scores})
        return jsonify(adjudication={"request_id": rid, "ts": now, "analyst": g.user, "outcome": outcome,
                                     "justification": just, "corrected_verdict": corrected})

    @app.get("/api/decisions/<rid>/adjudications")
    def adjudications(rid):
        return jsonify(adjudications=store.q(
            "SELECT ts, analyst, outcome, justification, corrected_verdict FROM adjudications "
            "WHERE request_id = %s ORDER BY ts", (rid,)))

    @app.get("/api/stats")
    def stats():
        by_verdict = {r["verdict"]: r["n"] for r in store.q("SELECT verdict, COUNT(*) AS n FROM decisions GROUP BY verdict")}
        by_route = {r["route"]: r["n"] for r in store.q("SELECT route, COUNT(*) AS n FROM decisions GROUP BY route")}
        by_type = {r["attack_type"]: r["n"] for r in store.q(
            "SELECT attack_type, COUNT(*) AS n FROM decisions WHERE verdict <> 'ALLOW' GROUP BY attack_type")}
        lat = store.q("""SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY (timings_ms->>'agents')::float) AS p50,
                                percentile_cont(0.95) WITHIN GROUP (ORDER BY (timings_ms->>'agents')::float) AS p95
                         FROM decisions WHERE route = 'ai'""")[0]
        timeline = store.q("""SELECT floor(ts / 10) * 10 AS bucket, verdict, COUNT(*) AS n FROM decisions
                              WHERE ts > %s GROUP BY 1, 2 ORDER BY 1""", (time.time() - 600,))
        w = store.q("SELECT entry FROM weight_updates WHERE NOT skipped ORDER BY ts DESC LIMIT 1")
        return jsonify(total=sum(by_verdict.values()), by_verdict=by_verdict, by_route=by_route,
                       by_attack_type=by_type, agent_latency_ms=lat, timeline=timeline,
                       weights=(w[0]["entry"]["new"] if w else None),
                       degraded=store.q("SELECT COUNT(*) AS n FROM decisions WHERE degraded")[0]["n"])

    @app.get("/api/weights")
    def weights():
        return jsonify(updates=[r["entry"] for r in store.q(
            "SELECT entry FROM weight_updates ORDER BY ts DESC LIMIT 50")])

    @app.get("/api/auth/events")
    def auth_events():
        return jsonify(events=auth.recent_events())

    @app.get("/api/users")
    def users():
        return jsonify(users=auth.list_users())

    @app.get("/health")
    def health():
        store.q("SELECT 1")
        return jsonify(status="ok")

    return app


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    cfg = load_config(os.environ.get("CONFIG"))
    store = Store()
    bus = make_bus()
    auth = Auth(DB_URL, cfg["auth"])
    made = auth.seed_from_env(os.environ)
    if made:
        log.info("created users from environment: %s", ", ".join(made))
    if not auth.user_count():
        log.warning("no users yet: set ADMIN_USERNAME / ADMIN_PASSWORD")
    start_consumer(store, bus)
    create_app(store, bus, auth, cfg).run(host="0.0.0.0", port=int(os.environ.get("PORT", 7002)), threaded=True)


if __name__ == "__main__":
    main()
