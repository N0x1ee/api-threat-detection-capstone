"""Gateway tests (SRS v1.1 AC-001, AC-002, AC-012, AC-022, FR-028, UI-005).

Fake agents are used so the tests are fast and need no trained models: the fake payload agent
reports a threat whenever the text contains the marker MALICIOUS_MARKER.
"""
import json
import logging
import os
import socket
import tempfile
import time
import unittest
from types import SimpleNamespace

from app.auth import Auth
from app.config import load_config
from app.pipeline import Pipeline
from app.server import create_app, resolve_identity
from demo_api.app import serve_in_thread

MARK = "MALICIOUS_MARKER"
logging.getLogger("werkzeug").setLevel(logging.ERROR)


class FakeAgent:
    def __init__(self, name, hot=0.95, cold=0.05):
        self.name, self.hot, self.cold = name, hot, cold

    def analyze(self, *args):
        text = json.dumps(args[0], default=str) if args and isinstance(args[0], dict) else ""
        s = self.hot if MARK in text else self.cold
        return SimpleNamespace(score=s, confidence=0.9, detail={"reason": f"{self.name} test reason"})


class FakeBehavior:
    def analyze(self, history, rate):
        return SimpleNamespace(score=0.05, confidence=0.5, detail={"reason": ""})


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class GatewayTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.log_path = os.path.join(cls.tmp, "access.log")
        cls.port = free_port()
        cls.server = serve_in_thread("127.0.0.1", cls.port, cls.log_path)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def make(self, **gw):
        cfg = load_config(overrides={"gateway": {"upstream": f"http://127.0.0.1:{self.port}", **gw}})
        pipe = Pipeline((FakeAgent("anomaly"), FakeAgent("payload"), FakeBehavior()), ":memory:", cfg=cfg)
        auth = Auth(":memory:", cfg["auth"])
        self.addCleanup(pipe.db.close)
        self.addCleanup(auth.close)
        return pipe, create_app(pipe, cfg, auth).test_client()

    def access_log(self):
        if not os.path.exists(self.log_path):
            return []
        with open(self.log_path) as f:
            return [json.loads(line) for line in f if line.strip()]

    # AC-001, AC-002
    def test_clean_request_forwarded_with_request_id(self):
        pipe, c = self.make()
        r = c.get("/gateway/products?page=2", headers={"User-Agent": "Mozilla/5.0"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("items", r.get_json())                 # body came from the demo API
        rid = r.headers["X-Request-ID"]
        self.assertEqual(len(rid), 32)
        self.assertTrue(any(e["request_id"] == rid for e in self.access_log()))
        row = pipe.db.execute("SELECT request_id, verdict FROM decisions").fetchone()
        self.assertEqual(row, (rid, "ALLOW"))

    # AC-012, FR-052, UI-005
    def test_block_not_forwarded_and_no_detail_leaked(self):
        pipe, c = self.make()
        r = c.get(f"/gateway/search?q=x'{MARK}", headers={"User-Agent": "Mozilla/5.0"})
        self.assertEqual(r.status_code, 403)
        body = r.get_data(as_text=True).lower()
        for word in ("score", "threshold", "agent", "explanation", "confidence", "reason", "weight"):
            self.assertNotIn(word, body)
        rid = r.headers["X-Request-ID"]
        self.assertFalse(any(e["request_id"] == rid for e in self.access_log()))
        self.assertEqual(pipe.db.execute("SELECT verdict FROM decisions WHERE request_id=?", (rid,)).fetchone()[0], "BLOCK")

    # FR-028
    def test_rate_limit_429_and_recorded(self):
        pipe, c = self.make(rate_limit={"max_requests": 3, "window_s": 10})
        codes = [c.get("/gateway/help", headers={"User-Agent": "Mozilla/5.0"}).status_code for _ in range(5)]
        self.assertEqual(codes[:3], [200, 200, 200])
        self.assertEqual(codes[3:], [429, 429])
        n = pipe.db.execute("SELECT COUNT(*) FROM decisions WHERE route='rate_limit'").fetchone()[0]
        self.assertEqual(n, 2)

    # AC-022 / SEC-037
    def test_spoofed_identity_headers_ignored(self):
        pipe, c = self.make()
        c.get("/gateway/help", headers={"User-Agent": "Mozilla/5.0", "X-User-Id": "victim",
                                        "X-Forwarded-For": "9.9.9.9"})
        user, ip, src = pipe.db.execute("SELECT user, ip, identity_source FROM decisions").fetchone()
        self.assertNotIn("victim", user)
        self.assertNotEqual(ip, "9.9.9.9")
        self.assertEqual(src, "source_ip")

    def test_rotating_spoofed_header_does_not_dodge_rate_limit(self):
        pipe, c = self.make(rate_limit={"max_requests": 3, "window_s": 10})
        codes = [c.get("/gateway/help", headers={"User-Agent": "Mozilla/5.0", "X-User-Id": f"u{i}"}).status_code
                 for i in range(5)]
        self.assertIn(429, codes)

    def test_trusted_proxy_mode_uses_headers(self):
        ident, src, ip = resolve_identity({"X-User-Id": "alice", "X-Forwarded-For": "5.6.7.8, 10.0.0.1"}, {},
                                          "10.0.0.1", trusted_proxy=True)
        self.assertEqual((src, ip), ("trusted_header", "5.6.7.8"))
        self.assertNotIn("alice", ident)                     # stored as a digest

    def test_identity_precedence(self):
        h = {"Authorization": "Bearer abc", "X-API-Key": "k"}
        self.assertEqual(resolve_identity(h, {"session": "s1"}, "1.1.1.1")[1], "session_cookie")
        self.assertEqual(resolve_identity(h, {}, "1.1.1.1")[1], "bearer_token")
        self.assertEqual(resolve_identity({"X-API-Key": "k"}, {}, "1.1.1.1")[1], "api_key")
        self.assertEqual(resolve_identity({}, {}, "1.1.1.1")[1:], ("source_ip", "1.1.1.1"))

    # UC-01 E3
    def test_upstream_down_gives_502(self):
        pipe, c = self.make(upstream=f"http://127.0.0.1:{free_port()}", upstream_timeout_s=1)
        r = c.get("/gateway/help", headers={"User-Agent": "Mozilla/5.0"})
        self.assertEqual(r.status_code, 502)
        self.assertIn("X-Request-ID", r.headers)

    def test_upstream_404_passed_through(self):
        pipe, c = self.make()
        r = c.get("/gateway/orders/999999/unknown", headers={"User-Agent": "Mozilla/5.0"})
        self.assertIn(r.status_code, (403, 404))             # blocked by us, or the API's own 404 passed through

    def test_post_body_forwarded(self):
        pipe, c = self.make()
        r = c.post("/gateway/feedback", json={"message": "Great service"}, headers={"User-Agent": "Mozilla/5.0"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["received_chars"], len("Great service"))

    def test_every_response_has_request_id(self):
        pipe, c = self.make()
        for url in ("/health", "/api/stats", "/gateway/does-not-exist", "/login"):
            self.assertIn("X-Request-ID", c.get(url, headers={"User-Agent": "Mozilla/5.0"}).headers)

    def test_errors_do_not_leak_internals(self):
        pipe, c = self.make()
        r = c.get("/gateway/does-not-exist", headers={"User-Agent": "Mozilla/5.0"})
        self.assertIn(r.status_code, (403, 404))
        self.assertNotIn("Traceback", r.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
