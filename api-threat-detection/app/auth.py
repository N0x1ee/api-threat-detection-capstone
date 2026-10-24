"""Analyst login: accounts, password hashing, sessions, roles, CSRF, lockout, audit (SRS v1.1 Section 8, ADD-28).

  - Passwords are stored only as salted scrypt hashes (werkzeug)                      SEC-009
  - No default or hard-coded accounts; the first admin is created by you              SEC-010
  - Server-side sessions, cookie HttpOnly + SameSite=Strict, idle expiry               SEC-011, ADD-28
  - Two roles: analyst and admin; admin-only operations checked on the server          SEC-007, SEC-012
  - Every login attempt and logout is recorded                                         SEC-016
  - State-changing requests need the session's CSRF token (X-CSRF-Token header)        SEC-034
  - Repeated failed logins lock that username + IP for a few minutes                   SEC-017 (T2)
"""
import hmac
import re
import secrets
from .dbcompat import connect
import threading
import time

from werkzeug.security import check_password_hash, generate_password_hash

ROLES = ("analyst", "admin")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
COOKIE_NAME = "atd_session"
# A real hash of a random throwaway password: used for unknown usernames so the
# response time does not reveal whether a username exists.
_DUMMY_HASH = generate_password_hash(secrets.token_hex(16))


class AuthError(ValueError):
    pass


class Auth:
    def __init__(self, db_path, cfg=None):
        c = {"session_idle_minutes": 30, "session_max_hours": 12, "cookie_secure": False,
             "max_failed_logins": 5, "lockout_minutes": 5, "min_password_length": 8}
        c.update(cfg or {})
        self.cfg = c
        self.db = connect(db_path)          # SQLite file or postgres:// URL
        self.lock = threading.Lock()
        self.sessions = {}            # token -> {"user", "role", "csrf", "created", "seen"}
        self.failures = {}            # (username, ip) -> [timestamps]
        with self.lock:
            self.db.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
                created REAL, active INTEGER DEFAULT 1)""")
            self.db.execute("""CREATE TABLE IF NOT EXISTS auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, username TEXT, ip TEXT, outcome TEXT)""")
            self.db.commit()

    def close(self):
        self.db.close()

    # ---------------------------------------------------------------- accounts
    def user_count(self):
        return self.db.execute("SELECT COUNT(*) FROM users WHERE active = 1").fetchone()[0]

    def add_user(self, username, password, role="analyst"):
        if not USERNAME_RE.match(username or ""):
            raise AuthError("username must be 3-32 characters: letters, digits, dot, dash or underscore")
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        if len(password or "") < self.cfg["min_password_length"]:
            raise AuthError(f"password must be at least {self.cfg['min_password_length']} characters")
        if password.lower() in ("password", "password1", "12345678", "admin123", "qwerty123", username.lower()):
            raise AuthError("password is too easy to guess")
        with self.lock:
            if self.db.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise AuthError(f"user {username!r} already exists")
            self.db.execute("INSERT INTO users (username, password_hash, role, created) VALUES (?,?,?,?)",
                            (username, generate_password_hash(password), role, time.time()))
            self.db.commit()

    def set_password(self, username, password):
        if len(password or "") < self.cfg["min_password_length"]:
            raise AuthError(f"password must be at least {self.cfg['min_password_length']} characters")
        with self.lock:
            cur = self.db.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                                  (generate_password_hash(password), username))
            self.db.commit()
        if not cur.rowcount:
            raise AuthError(f"no user {username!r}")
        self.end_sessions_for(username)

    def deactivate(self, username):
        with self.lock:
            self.db.execute("UPDATE users SET active = 0 WHERE username = ?", (username,))
            self.db.commit()
        self.end_sessions_for(username)

    def list_users(self):
        return [{"username": u, "role": r, "active": bool(a)} for u, r, a in
                self.db.execute("SELECT username, role, active FROM users ORDER BY username")]

    def seed_from_env(self, env):
        """Create accounts from ADMIN_USERNAME/ADMIN_PASSWORD and ANALYST_USERNAME/ANALYST_PASSWORD
        if they are set and do not exist yet. Returns the usernames created."""
        made = []
        for prefix, role in (("ADMIN", "admin"), ("ANALYST", "analyst")):
            u, p = env.get(f"{prefix}_USERNAME"), env.get(f"{prefix}_PASSWORD")
            if u and p and not self.db.execute("SELECT 1 FROM users WHERE username = ?", (u,)).fetchone():
                self.add_user(u, p, role)
                made.append(u)
        return made

    # ---------------------------------------------------------------- login
    def _event(self, username, ip, outcome):
        with self.lock:
            self.db.execute("INSERT INTO auth_events (ts, username, ip, outcome) VALUES (?,?,?,?)",
                            (time.time(), (username or "")[:64], ip, outcome))
            self.db.commit()

    def locked_out(self, username, ip, now=None):
        now = time.time() if now is None else now
        window = self.cfg["lockout_minutes"] * 60
        recent = [t for t in self.failures.get((username, ip), []) if t > now - window]
        self.failures[(username, ip)] = recent
        return len(recent) >= self.cfg["max_failed_logins"]

    def login(self, username, password, ip):
        """Returns (token, session) on success. Raises AuthError with a generic message otherwise."""
        username = (username or "").strip()
        if self.locked_out(username, ip):
            self._event(username, ip, "locked_out")
            raise AuthError("too many failed attempts, try again in a few minutes")
        row = self.db.execute("SELECT password_hash, role, active FROM users WHERE username = ?",
                              (username,)).fetchone()
        ok = check_password_hash(row[0] if row else _DUMMY_HASH, password or "")
        if not row or not ok or not row[2]:
            self.failures.setdefault((username, ip), []).append(time.time())
            self._event(username, ip, "unknown_user" if not row else ("inactive" if not row[2] else "bad_password"))
            raise AuthError("wrong username or password")
        self.failures.pop((username, ip), None)
        token = secrets.token_urlsafe(32)
        now = time.time()
        sess = {"user": username, "role": row[1], "csrf": secrets.token_urlsafe(24), "created": now, "seen": now}
        with self.lock:
            self.sessions[token] = sess
        self._event(username, ip, "success")
        return token, sess

    def session(self, token, now=None):
        """Valid session for this token, refreshing its idle timer, or None."""
        if not token:
            return None
        now = time.time() if now is None else now
        with self.lock:
            s = self.sessions.get(token)
            if not s:
                return None
            idle = now - s["seen"] > self.cfg["session_idle_minutes"] * 60
            too_old = now - s["created"] > self.cfg["session_max_hours"] * 3600
            if idle or too_old:
                del self.sessions[token]
                return None
            s["seen"] = now
            return s

    def logout(self, token, ip):
        with self.lock:
            s = self.sessions.pop(token, None)
        if s:
            self._event(s["user"], ip, "logout")

    def end_sessions_for(self, username):
        with self.lock:
            for t in [t for t, s in self.sessions.items() if s["user"] == username]:
                del self.sessions[t]

    @staticmethod
    def csrf_ok(sess, sent):
        return bool(sess and sent) and hmac.compare_digest(sess["csrf"], sent)

    def recent_events(self, limit=50):
        return [{"ts": ts, "username": u, "ip": ip, "outcome": o} for ts, u, ip, o in self.db.execute(
            "SELECT ts, username, ip, outcome FROM auth_events ORDER BY id DESC LIMIT ?", (limit,))]
