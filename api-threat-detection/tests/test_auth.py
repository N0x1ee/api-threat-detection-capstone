"""Login and access-control tests (SRS v1.1 AC-015, AC-025, SEC-006 to SEC-016, SEC-034)."""
import time
import unittest
from types import SimpleNamespace

from app.auth import COOKIE_NAME, Auth, AuthError
from app.config import load_config
from app.pipeline import Pipeline
from app.server import create_app

PW = "correct-horse-42"


class Quiet:
    def analyze(self, *a):
        return SimpleNamespace(score=0.1, confidence=0.5, detail={"reason": ""})


class AuthUnitTest(unittest.TestCase):
    def setUp(self):
        self.auth = Auth(":memory:", {"max_failed_logins": 3, "lockout_minutes": 5, "session_idle_minutes": 30})
        self.addCleanup(self.auth.close)
        self.auth.add_user("alice", PW, "admin")

    def test_password_is_hashed(self):                       # SEC-009
        stored = self.auth.db.execute("SELECT password_hash FROM users").fetchone()[0]
        self.assertNotIn(PW, stored)
        self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_weak_or_invalid_rejected(self):
        for name, pw in (("bob", "short"), ("bob", "password"), ("b", PW), ("bob bad", PW)):
            with self.assertRaises(AuthError):
                self.auth.add_user(name, pw)
        with self.assertRaises(AuthError):
            self.auth.add_user("alice", PW)                   # duplicate
        with self.assertRaises(AuthError):
            self.auth.add_user("carol", PW, "root")           # unknown role

    def test_login_and_generic_errors(self):
        tok, sess = self.auth.login("alice", PW, "1.1.1.1")
        self.assertEqual(sess["role"], "admin")
        self.assertIs(self.auth.session(tok), sess)
        with self.assertRaises(AuthError) as a:
            self.auth.login("alice", "wrong-password", "1.1.1.1")
        with self.assertRaises(AuthError) as b:
            self.auth.login("nobody", "wrong-password", "1.1.1.1")
        self.assertEqual(str(a.exception), str(b.exception))  # same message: no username probing

    def test_lockout_after_failures(self):                   # SEC-017
        for _ in range(3):
            with self.assertRaises(AuthError):
                self.auth.login("alice", "nope-nope", "2.2.2.2")
        with self.assertRaises(AuthError) as e:
            self.auth.login("alice", PW, "2.2.2.2")           # right password, still locked
        self.assertIn("too many", str(e.exception))
        self.auth.login("alice", PW, "3.3.3.3")              # other IP not affected

    def test_idle_expiry(self):                              # SEC-011
        tok, sess = self.auth.login("alice", PW, "1.1.1.1")
        self.assertIsNone(self.auth.session(tok, now=time.time() + 31 * 60))
        self.assertIsNone(self.auth.session(tok))            # removed for good

    def test_events_recorded(self):                          # SEC-016
        self.auth.login("alice", PW, "1.1.1.1")
        with self.assertRaises(AuthError):
            self.auth.login("alice", "bad-password", "1.1.1.1")
        outcomes = [e["outcome"] for e in self.auth.recent_events()]
        self.assertEqual(outcomes[:2], ["bad_password", "success"])

    def test_password_change_ends_sessions(self):
        tok, _ = self.auth.login("alice", PW, "1.1.1.1")
        self.auth.set_password("alice", "another-good-one")
        self.assertIsNone(self.auth.session(tok))

    def test_disabled_user_cannot_login(self):
        self.auth.add_user("bob", PW)
        self.auth.deactivate("bob")
        with self.assertRaises(AuthError):
            self.auth.login("bob", PW, "1.1.1.1")

    def test_seed_from_env(self):
        made = self.auth.seed_from_env({"ANALYST_USERNAME": "eve", "ANALYST_PASSWORD": PW})
        self.assertEqual(made, ["eve"])
        self.assertEqual(self.auth.seed_from_env({"ANALYST_USERNAME": "eve", "ANALYST_PASSWORD": PW}), [])


class AccessControlTest(unittest.TestCase):
    def setUp(self):
        cfg = load_config()
        self.pipe = Pipeline((Quiet(), Quiet(), Quiet()), ":memory:", cfg=cfg)
        self.auth = Auth(":memory:", cfg["auth"])
        self.addCleanup(self.pipe.db.close)
        self.addCleanup(self.auth.close)
        self.auth.add_user("admin1", PW, "admin")
        self.auth.add_user("analyst1", PW, "analyst")
        self.c = create_app(self.pipe, cfg, self.auth).test_client()

    def login(self, user):
        r = self.c.post("/login", json={"username": user, "password": PW})
        self.assertEqual(r.status_code, 200)
        return self.c.get("/api/me").get_json()["csrf"]

    def test_anonymous_blocked(self):                        # SEC-006 / AC-015
        self.assertEqual(self.c.get("/api/stats").status_code, 401)
        self.assertEqual(self.c.post("/api/reset").status_code, 401)
        r = self.c.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        self.assertEqual(self.c.get("/static/index.html").status_code, 302)
        self.assertEqual(self.c.get("/login").status_code, 200)
        self.assertEqual(self.c.get("/health").status_code, 200)

    def test_cookie_flags(self):                             # ADD-28
        r = self.c.post("/login", json={"username": "analyst1", "password": PW})
        cookie = r.headers["Set-Cookie"]
        self.assertIn(COOKIE_NAME, cookie)
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertNotIn(PW, cookie)

    def test_wrong_password_401(self):
        self.assertEqual(self.c.post("/login", json={"username": "analyst1", "password": "nope-nope"}).status_code, 401)

    def test_analyst_can_use_dashboard_but_not_admin(self):  # SEC-007 / SEC-012
        csrf = self.login("analyst1")
        self.assertEqual(self.c.get("/api/stats").status_code, 200)
        self.assertEqual(self.c.post("/api/analyze", json={"endpoint": "/help"},
                                     headers={"X-CSRF-Token": csrf}).status_code, 200)
        self.assertEqual(self.c.post("/api/reset", headers={"X-CSRF-Token": csrf}).status_code, 403)
        self.assertEqual(self.c.get("/api/auth/events").status_code, 403)

    def test_admin_can_reset(self):
        csrf = self.login("admin1")
        self.assertEqual(self.c.post("/api/reset", headers={"X-CSRF-Token": csrf}).status_code, 200)
        self.assertEqual(self.c.get("/api/auth/events").status_code, 200)

    def test_csrf_required(self):                            # SEC-034
        csrf = self.login("admin1")
        self.assertEqual(self.c.post("/api/reset").status_code, 403)
        self.assertEqual(self.c.post("/api/reset", headers={"X-CSRF-Token": "forged"}).status_code, 403)
        self.assertEqual(self.c.post("/api/reset", headers={"X-CSRF-Token": csrf}).status_code, 200)

    def test_logout_ends_session(self):
        csrf = self.login("analyst1")
        self.assertEqual(self.c.post("/logout", headers={"X-CSRF-Token": csrf}).status_code, 200)
        self.assertEqual(self.c.get("/api/stats").status_code, 401)

    def test_override_records_analyst(self):                 # FR-081
        csrf = self.login("analyst1")
        rec = self.c.post("/api/analyze", json={"endpoint": "/search", "query": "q=x'"},
                          headers={"X-CSRF-Token": csrf}).get_json()
        r = self.c.post("/api/override", json={"id": rec["id"], "action": "block"}, headers={"X-CSRF-Token": csrf})
        self.assertEqual(r.get_json()["override_by"], "analyst1")
        row = self.pipe.db.execute("SELECT override, override_by FROM decisions WHERE id=?", (rec["id"],)).fetchone()
        self.assertEqual(row, ("block", "analyst1"))

    def test_gateway_stays_public(self):
        r = self.c.get("/gateway/help", headers={"User-Agent": "Mozilla/5.0"})
        self.assertNotEqual(r.status_code, 401)              # the protected API's traffic never needs a login

    def test_login_lockout_returns_429(self):
        for _ in range(5):
            self.c.post("/login", json={"username": "analyst1", "password": "bad-bad-bad"})
        self.assertEqual(self.c.post("/login", json={"username": "analyst1", "password": PW}).status_code, 429)


if __name__ == "__main__":
    unittest.main()
