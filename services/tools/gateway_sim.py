"""Python stand-in for the Spring Boot gateway: does exactly the gateway's steps 1-4 from
ARCHITECTURE.md. Used for end-to-end tests where Java can't run, and as a reference for the
Java implementation.

    BUS=redis python tools/gateway_sim.py            # sends a few normal + attack requests
"""
import json
import os
import sys
import time
import uuid

import redis
import requests

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from common.bus import make_bus  # noqa: E402

FF = os.environ.get("FASTFILTER_URL", "http://localhost:7001")
VERDICT_TIMEOUT_S = float(os.environ.get("VERDICT_TIMEOUT_MS", 400)) / 1000
r = redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)
bus = make_bus()


def handle(method, path, query="", body="", headers=None, ip="10.0.0.5", identity=None):
    rid = uuid.uuid4().hex
    ev = {"request_id": rid, "ts": time.time(), "method": method, "path": path, "query": query, "body": body,
          "headers": headers or {"User-Agent": "Mozilla/5.0"}, "ip": ip,
          "identity": identity or ip, "identity_source": "source_ip"}
    t0 = time.perf_counter()
    chk = requests.post(f"{FF}/check", json=ev, timeout=2).json()
    ev["endpoint"] = chk["endpoint"]
    if not chk["refer"]:
        bus.publish("decisions", rid, {"request_id": rid, "ts": time.time(), "route": "fast_filter",
                                       "verdict": "ALLOW", "score": None, "request": ev})
        return "ALLOW", "fast_filter", (time.perf_counter() - t0) * 1000
    ev["fast_filter"] = {k: chk[k] for k in ("reasons", "rule_ids", "rules_version", "rate")}
    ev["history"], ev["deadline_ms"] = chk["history"], 150
    bus.publish("requests.suspicious", rid, ev)
    got = r.blpop(f"verdict:{rid}", timeout=VERDICT_TIMEOUT_S)
    ms = (time.perf_counter() - t0) * 1000
    if not got:
        return "FLAG", "timeout (fail_open_flag)", ms
    return json.loads(got[1])["verdict"], "ai", ms


if __name__ == "__main__":
    cases = [("GET", "/products", "page=2", ""), ("GET", "/search", "q=shoes", ""),
             ("GET", "/search", "q=x' UNION SELECT password FROM users--", ""),
             ("GET", "/files", "name=../../../../etc/passwd", ""),
             ("POST", "/feedback", "", "msg=<script>alert(1)</script>"),
             ("GET", "/products/12", "", "")]
    for c in cases:
        v, route, ms = handle(*c)
        print(f"{v:6s} {route:22s} {ms:7.1f} ms  {c[0]} {c[1]}?{c[2]}{c[3]}")
