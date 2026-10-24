"""connect(): SQLite for a file path / ":memory:", PostgreSQL for a postgres:// URL.

The PostgreSQL wrapper accepts the SQLite dialect used in this codebase ("?" placeholders,
INTEGER PRIMARY KEY AUTOINCREMENT, REAL) so auth.py runs unchanged on both.
"""
import re
import sqlite3
import threading


def connect(target):
    if str(target).startswith(("postgres://", "postgresql://")):
        return PgCompat(target)
    return sqlite3.connect(target, check_same_thread=False)


class PgCompat:
    _subs = ((re.compile(r"INTEGER PRIMARY KEY AUTOINCREMENT", re.I), "SERIAL PRIMARY KEY"),
             (re.compile(r"\bREAL\b"), "DOUBLE PRECISION"))

    def __init__(self, url):
        import psycopg
        self.conn = psycopg.connect(url, autocommit=True)
        self.lock = threading.Lock()

    def execute(self, sql, params=()):
        for pat, rep in self._subs:
            sql = pat.sub(rep, sql)
        sql = sql.replace("%", "%%").replace("?", "%s")
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(sql, params)
        return cur

    def commit(self):
        pass

    def close(self):
        self.conn.close()
