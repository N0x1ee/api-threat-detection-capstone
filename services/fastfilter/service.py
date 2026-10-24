"""Fast Filter service (Python + Redis). The gateway calls POST /check for every request.

Reuses the rules engine from api-threat-detection/app/fastfilter.py; rate counters, endpoint
history and the clean-payload cache live in Redis so every gateway instance shares them.
"""
import os
import sys
import time

ROOT = os.environ.get("APP_ROOT", os.path.join(os.path.dirname(__file__), "..", "..", "api-threat-detection"))
sys.path.insert(0, os.path.abspath(ROOT))

import redis  # noqa: E402
from flask import Flask, jsonify, request  # noqa: E402

from app.config import load_config  # noqa: E402
from app.fastfilter import FastFilter, load_rules  # noqa: E402
from app.traffic import normalize_endpoint  # noqa: E402

HIST_KEEP, HIST_SEND = 60, 20


class RedisCleanCache:
    """Duck-types the OrderedDict FastFilter uses for its clean-payload cache (FR-022, FR-023)."""

    def __init__(self, r, ttl):
        self.r, self.ttl = r, ttl

    def get(self, key):
        exp = self.r.get(f"ff:cache:{key}")
        return float(exp) if exp else None

    def pop(self, key, default=None):
        self.r.delete(f"ff:cache:{key}")
        return default

    def __setitem__(self, key, expiry):
        self.r.set(f"ff:cache:{key}", expiry, ex=max(1, int(self.ttl)))

    def __len__(self):
        return 0                      # Redis TTL bounds the size; FastFilter never needs to evict


def create_app(r=None, cfg=None):
    cfg = cfg or load_config(os.environ.get("CONFIG"))
    ff_cfg = cfg["fast_filter"]
    rules_path = ff_cfg.get("rules_file")
    if rules_path and not os.path.isabs(rules_path):
        rules_path = os.path.join(ROOT, rules_path)
    r = r or redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
    ff = FastFilter(load_rules(rules_path), ff_cfg["rate_threshold"], ff_cfg["rate_window_s"],
                    ff_cfg["max_payload_chars"], ff_cfg.get("cache_ttl_s", 60))
    ff.clean_cache = RedisCleanCache(r, ff.cache_ttl_s)
    window = float(ff_cfg["rate_window_s"])
    app = Flask(__name__)

    @app.post("/check")
    def check():
        t0 = time.perf_counter()
        ev = request.get_json(silent=True) or {}
        req = {"method": (ev.get("method") or "GET").upper(), "path": ev.get("path") or "/",
               "query": ev.get("query") or "", "body": ev.get("body") or "", "headers": ev.get("headers") or {}}
        req["endpoint"] = normalize_endpoint(req["path"])
        ident = ev.get("identity") or ev.get("ip") or "anonymous"
        now = time.time()
        p = r.pipeline()
        p.zadd(f"ff:rate:{ident}", {f"{now}:{ev.get('request_id', '')}": now})
        p.zremrangebyscore(f"ff:rate:{ident}", 0, now - window)
        p.zcard(f"ff:rate:{ident}")
        p.expire(f"ff:rate:{ident}", int(window) + 5)
        p.rpush(f"ff:hist:{ident}", req["endpoint"])
        p.ltrim(f"ff:hist:{ident}", -HIST_KEEP, -1)
        p.expire(f"ff:hist:{ident}", 3600)
        p.lrange(f"ff:hist:{ident}", -HIST_SEND, -1)
        out = p.execute()
        rate, history = out[2], out[-1]
        refer, reasons, rule_ids, cached = ff.check(req, rate, now)
        r.hincrby("ff:stats", "referred" if refer else "cleared", 1)
        return jsonify(refer=refer, reasons=reasons, rule_ids=rule_ids, rules_version=ff.version, cached=cached,
                       rate=rate, history=history, endpoint=req["endpoint"],
                       latency_ms=round((time.perf_counter() - t0) * 1000, 3))

    @app.get("/stats")
    def stats():
        s = {k: int(v) for k, v in r.hgetall("ff:stats").items()}
        total = s.get("cleared", 0) + s.get("referred", 0)
        return jsonify(**s, cleared_share=(s.get("cleared", 0) / total) if total else None,
                       rules_version=ff.version)            # FR-026

    @app.get("/health")
    def health():
        r.ping()
        return jsonify(status="ok", rules_version=ff.version)

    return app


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", 7001)), threaded=True)
