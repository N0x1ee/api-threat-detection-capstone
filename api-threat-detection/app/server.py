"""Web server: the gateway (/gateway/...), the dashboard API (/api/...) and the traffic simulator.

Gateway behaviour (SRS v1.1 Section 4.1, 4.3, 4.6, ADD-32):
  - every response carries X-Request-ID (FR-003, FR-055, UI-004)
  - identity = session cookie, bearer token, API key (all as digests), else source IP (FR-009);
    client-sent X-User-Id / X-Forwarded-For are ignored unless gateway.trusted_proxy is true
  - per-identity rate limit -> HTTP 429 with a decision record (FR-027, FR-028)
  - ALLOW and FLAG are forwarded to the protected API and its response is returned (FR-050, FR-053)
  - BLOCK -> HTTP 403, nothing forwarded (FR-051)
  - clients never see scores, thresholds, agent output or explanations (FR-052, UI-005, XAI-017)
"""
import hashlib
import logging
import os
import random
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections import OrderedDict, deque

from flask import Flask, Response, g, jsonify, redirect, request

from .auth import COOKIE_NAME, Auth, AuthError
from .traffic import ATTACK_KINDS, generate_session, mixed_sessions, normalize_endpoint

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
log = logging.getLogger("gateway")

PUBLIC_PATHS = {"/login", "/health", "/static/login.html", "/static/chart.umd.js", "/favicon.ico"}
ADMIN_ONLY = {"/api/reset", "/api/auth/events", "/api/users"}
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
SESSION_COOKIES = ("session", "sessionid", "PHPSESSID", "JSESSIONID", "connect.sid")
FORWARD_HEADERS = ("Content-Type", "Accept", "Accept-Language", "Authorization", "Cookie", "User-Agent")
HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailers",
              "transfer-encoding", "upgrade", "content-length", "content-encoding", "server", "date"}


def _digest(value):
    return hashlib.sha256(value.encode("utf-8", "ignore")).hexdigest()[:16]


def resolve_identity(headers, cookies, remote_addr, trusted_proxy=False):
    """FR-009 precedence: session cookie > bearer token > API key > source IP. Secrets are hashed (SEC-025).
    Returns (identity, source, client_ip)."""
    client_ip = remote_addr or "0.0.0.0"
    if trusted_proxy and headers.get("X-Forwarded-For"):
        client_ip = headers["X-Forwarded-For"].split(",")[0].strip()
    if trusted_proxy and headers.get("X-User-Id"):
        return "user:" + _digest(headers["X-User-Id"]), "trusted_header", client_ip
    for name in SESSION_COOKIES:
        if cookies.get(name):
            return "sess:" + _digest(cookies[name]), "session_cookie", client_ip
    auth = headers.get("Authorization", "")
    if auth.lower().startswith("bearer ") and len(auth) > 7:
        return "tok:" + _digest(auth[7:].strip()), "bearer_token", client_ip
    if headers.get("X-API-Key"):
        return "key:" + _digest(headers["X-API-Key"]), "api_key", client_ip
    return "ip:" + client_ip, "source_ip", client_ip


class RateLimiter:
    """Sliding-window request counter per identity (in memory; Redis is a T2 option)."""

    def __init__(self, max_requests, window_s, max_ids=20000):
        self.max_requests, self.window_s, self.max_ids = max_requests, window_s, max_ids
        self.hits = OrderedDict()
        self.lock = threading.Lock()

    def hit(self, identity, now=None):
        """Record one request. Returns (allowed, count_in_window)."""
        now = time.time() if now is None else now
        with self.lock:
            dq = self.hits.pop(identity, None) or deque()
            while dq and dq[0] <= now - self.window_s:
                dq.popleft()
            dq.append(now)
            self.hits[identity] = dq
            if len(self.hits) > self.max_ids:
                self.hits.popitem(last=False)
            return len(dq) <= self.max_requests, len(dq)


def forward(upstream, method, path, query, body, headers, request_id, timeout):
    """Send the request to the protected API. Returns (status, headers, body) or None if unreachable."""
    url = upstream.rstrip("/") + path + (("?" + query) if query else "")
    out_headers = {k: headers[k] for k in FORWARD_HEADERS if headers.get(k)}
    out_headers["X-Request-ID"] = request_id
    req = urllib.request.Request(url, data=body if body else None, method=method, headers=out_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:          # 4xx/5xx from the protected API: pass it through
        return e.code, dict(e.headers), e.read()
    except (urllib.error.URLError, TimeoutError, ConnectionError, OSError):
        return None


class Simulator:
    def __init__(self, pipeline):
        self.pipe, self.thread = pipeline, None
        self.state = {"running": False, "done": 0, "total": 0, "mode": ""}
        self.stop_flag = False

    def start(self, mode, sessions, novel, delay=0.03):
        if self.thread and self.thread.is_alive():
            return False
        rng, t0 = random.Random(), time.time()
        if mode == "mixed":
            reqs = mixed_sessions(rng, sessions, t0, novel_share=0.4 if novel else 0.0)
        else:
            reqs, t = [], t0
            for _ in range(sessions):
                s = generate_session(rng, mode, t, novel=novel)
                reqs += s
                t = s[-1]["ts"] + 1
        self.stop_flag = False
        self.state = {"running": True, "done": 0, "total": len(reqs), "mode": mode}
        self.thread = threading.Thread(target=self._run, args=(reqs, delay), daemon=True)
        self.thread.start()
        return True

    def _run(self, reqs, delay):
        for r in reqs:
            if self.stop_flag:
                break
            r.setdefault("request_id", uuid.uuid4().hex)
            r.setdefault("identity_source", "simulator")
            self.pipe.process(r, learn=True)
            self.state["done"] += 1
            time.sleep(delay)
        self.state["running"] = False


def create_app(pipeline, cfg=None, auth=None):
    cfg = cfg or pipeline.cfg
    gw = cfg["gateway"]
    auth = auth or Auth(":memory:", cfg.get("auth"))
    app = Flask(__name__, static_folder=os.path.join(ROOT, "static"), static_url_path="/static")
    app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024     # hard cap on what Flask will read at all
    sim = Simulator(pipeline)
    limiter = RateLimiter(gw["rate_limit"]["max_requests"], gw["rate_limit"]["window_s"])

    @app.before_request
    def assign_request_id():
        g.request_id = uuid.uuid4().hex

    @app.before_request
    def require_login():
        """SEC-006/007/012/034: everything except the gateway, /health and the login page needs a session;
        admin-only paths need the admin role; state-changing calls need the CSRF token."""
        path = request.path
        g.user = g.role = None
        if path.startswith("/gateway/") or path in PUBLIC_PATHS:
            return None
        sess = auth.session(request.cookies.get(COOKIE_NAME))
        if not sess:
            if path.startswith("/api/"):
                return jsonify(error="login required"), 401
            return redirect("/login")
        g.user, g.role, g.session = sess["user"], sess["role"], sess
        if request.method in STATE_CHANGING and not auth.csrf_ok(sess, request.headers.get("X-CSRF-Token")):
            return jsonify(error="missing or invalid CSRF token"), 403
        if path in ADMIN_ONLY and sess["role"] != "admin":
            return jsonify(error="administrator role required"), 403
        return None

    @app.after_request
    def add_request_id(resp):
        resp.headers["X-Request-ID"] = g.get("request_id", "")
        return resp

    @app.errorhandler(Exception)
    def internal_error(e):                  # SEC-033: no stack traces or component names to clients
        code = getattr(e, "code", 500)
        if not isinstance(code, int) or code < 400:
            code = 500
        if code >= 500:
            log.exception("unhandled error, request %s", g.get("request_id"))
        return jsonify(error="request failed", request_id=g.get("request_id")), code

    @app.get("/")
    def index():
        return app.send_static_file("index.html")

    @app.get("/login")
    def login_page():
        if auth.session(request.cookies.get(COOKIE_NAME)):
            return redirect("/")
        return app.send_static_file("login.html")

    @app.post("/login")
    def login():
        d = request.get_json(silent=True) or request.form
        try:
            token, sess = auth.login(d.get("username", ""), d.get("password", ""), request.remote_addr or "")
        except AuthError as e:
            code = 429 if "too many" in str(e) else 401
            return jsonify(error=str(e)), code
        resp = jsonify(ok=True, user=sess["user"], role=sess["role"])
        resp.set_cookie(COOKIE_NAME, token, httponly=True, samesite="Strict", secure=bool(cfg["auth"]["cookie_secure"]),
                        path="/", max_age=int(cfg["auth"]["session_max_hours"] * 3600))
        return resp

    @app.post("/logout")
    def logout():
        auth.logout(request.cookies.get(COOKIE_NAME), request.remote_addr or "")
        resp = jsonify(ok=True)
        resp.delete_cookie(COOKIE_NAME, path="/", samesite="Strict")
        return resp

    @app.get("/api/me")
    def me():
        return jsonify(user=g.user, role=g.role, csrf=g.session["csrf"],
                       idle_minutes=cfg["auth"]["session_idle_minutes"])

    @app.get("/api/auth/events")
    def auth_events():
        return jsonify(events=auth.recent_events())

    @app.get("/api/users")
    def users():
        return jsonify(users=auth.list_users())

    @app.get("/health")
    def health():                           # public: status only, no detail
        return jsonify(status="ok")

    # ----- the real gateway: everything under /gateway/ is inspected, then forwarded or blocked
    @app.route("/gateway/", defaults={"p": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    @app.route("/gateway/<path:p>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
    def gateway(p):
        rid = g.request_id
        path = "/" + p
        raw_body = request.get_data(cache=False) or b""
        limit = int(gw["max_inspect_bytes"])
        inspect_body = raw_body[:limit].decode("utf-8", "replace")
        identity, source, client_ip = resolve_identity(request.headers, request.cookies, request.remote_addr,
                                                       bool(gw["trusted_proxy"]))
        req = {"method": request.method, "path": path, "endpoint": normalize_endpoint(path),
               "query": request.query_string.decode("utf-8", "replace"), "body": inspect_body,
               "headers": dict(request.headers), "ip": client_ip, "user": identity, "ts": time.time(),
               "label": None, "request_id": rid, "identity_source": source,
               "truncated": len(raw_body) > limit}

        allowed, count = limiter.hit(identity, req["ts"])
        if not allowed:
            pipeline.record_rate_limited(req, count, gw["rate_limit"]["max_requests"], gw["rate_limit"]["window_s"])
            resp = jsonify(error="too many requests", request_id=rid)
            resp.headers["Retry-After"] = str(int(gw["rate_limit"]["window_s"]))
            return resp, 429

        rec = pipeline.process(req)
        if rec["verdict"] == "BLOCK":
            return jsonify(error="request blocked", request_id=rid), 403

        fwd = forward(gw["upstream"], request.method, path, req["query"], raw_body, request.headers, rid,
                      gw["upstream_timeout_s"])
        if fwd is None:
            return jsonify(error="upstream unavailable", request_id=rid), 502
        status, headers, body = fwd
        resp = Response(body, status=status)
        for k, v in headers.items():
            if k.lower() not in HOP_BY_HOP and k.lower() != "x-request-id":
                resp.headers[k] = v
        return resp

    # ----- used by the dashboard's "try a request" box
    @app.post("/api/analyze")
    def analyze():
        d = request.get_json(force=True, silent=True) or {}
        path = d.get("endpoint") or "/search"
        ua = d.get("user_agent", "Mozilla/5.0 (Windows NT 10.0) Chrome/118.0")
        user = d.get("user") or "demo-user"
        req = {"method": d.get("method", "GET"), "path": path, "endpoint": normalize_endpoint(path),
               "query": d.get("query", ""), "body": d.get("body", ""),
               "headers": {"Host": "api.shop.example", "Accept": "application/json", "User-Agent": ua},
               "ip": "127.0.0.1", "user": user, "ts": time.time(), "label": None,
               "request_id": g.request_id, "identity_source": "dashboard"}
        return jsonify(pipeline.public(pipeline.process(req)))

    @app.get("/api/stats")
    def stats():
        s = pipeline.stats()
        s["simulator"] = sim.state
        return jsonify(s)

    @app.post("/api/simulate")
    def simulate():
        d = request.get_json(force=True, silent=True) or {}
        mode = d.get("mode", "mixed")
        if mode not in ["mixed", "normal", "recon"] + ATTACK_KINDS:
            return jsonify(error="unknown mode"), 400
        ok = sim.start(mode, int(min(max(d.get("sessions", 15), 1), 200)), bool(d.get("novel", False)))
        return jsonify(started=ok)

    @app.post("/api/simulate/stop")
    def stop():
        sim.stop_flag = True
        return jsonify(ok=True)

    @app.post("/api/override")
    def override():
        d = request.get_json(force=True, silent=True) or {}
        rec = pipeline.override(int(d.get("id", -1)), d.get("action", ""), analyst=g.user)
        return (jsonify(pipeline.public(rec)), 200) if rec else (jsonify(error="not found"), 404)

    @app.post("/api/reset")
    def reset():
        sim.stop_flag = True
        time.sleep(0.1)
        pipeline.reset_all()
        return jsonify(ok=True)

    return app
