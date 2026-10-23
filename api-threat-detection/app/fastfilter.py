"""Rule-based fast filter, driven by rules/fast_filter.json (SRS v1.1 Section 4.2).

FR-013 runs on every request before any model     FR-016 rules live in a versioned file
FR-017 signature matches are always referred       FR-019 unknown endpoints referred
FR-020 size/header bounds referred                 FR-021 matching rule IDs recorded
FR-022 cache key includes a payload digest         FR-023 cache TTL + size bound
FR-024 a cached "clean" result never covers a signature match (only clean results are cached)
SEC-030 patterns checked for catastrophic backtracking at load time
"""
import hashlib
import json
import os
import re
import time
from collections import OrderedDict

from .traffic import normalize_text

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES = os.path.join(ROOT, "rules", "fast_filter.json")
KINDS = {"endpoint", "ua_missing", "ua_regex", "rate", "payload_chars", "payload_regex",
         "payload_length", "header_bounds"}
# a quantified group that itself contains a quantifier, e.g. (a+)+ or (\w*)* : classic ReDoS shape
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*[+*{]")


class RulesError(ValueError):
    pass


def load_rules(path=None):
    path = path or DEFAULT_RULES
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        raise RulesError(f"fast filter rules file not found: {path}") from None
    except json.JSONDecodeError as e:
        raise RulesError(f"{path} is not valid JSON: {e}") from None
    if not data.get("version"):
        raise RulesError("rules file needs a 'version'")
    if not isinstance(data.get("endpoints"), list) or not data["endpoints"]:
        raise RulesError("rules file needs a non-empty 'endpoints' list")
    seen = set()
    for r in data.get("rules", []):
        rid = r.get("id")
        if not rid or rid in seen:
            raise RulesError(f"rule id missing or duplicated: {rid!r}")
        seen.add(rid)
        if r.get("kind") not in KINDS:
            raise RulesError(f"rule {rid}: unknown kind {r.get('kind')!r}")
        if "pattern" in r:
            if _NESTED_QUANTIFIER.search(r["pattern"]):
                raise RulesError(f"rule {rid}: nested quantifier risks catastrophic backtracking")
            try:
                r["_re"] = re.compile(r["pattern"], re.I)
            except re.error as e:
                raise RulesError(f"rule {rid}: bad regular expression: {e}") from None
        if r["kind"] in ("ua_regex", "payload_regex") and "_re" not in r:
            raise RulesError(f"rule {rid}: needs a 'pattern'")
        if r["kind"] == "payload_chars" and not r.get("chars"):
            raise RulesError(f"rule {rid}: needs 'chars'")
    return data


class FastFilter:
    """Returns (refer_to_agents, reasons, rule_ids, from_cache)."""

    def __init__(self, rules=None, rate_threshold=8, rate_window_s=10, max_payload_chars=400,
                 cache_ttl_s=60, cache_size=5000):
        self.rules = rules or load_rules()
        self.version = self.rules["version"]
        self.endpoints = set(self.rules["endpoints"])
        self.rate_threshold, self.rate_window_s = rate_threshold, rate_window_s
        self.max_payload_chars = max_payload_chars
        self.cache_ttl_s, self.cache_size = cache_ttl_s, cache_size
        self.clean_cache = OrderedDict()   # key -> expiry time; stands in for the Redis decision cache

    @staticmethod
    def payload_text(req):
        # path + query + body, decoded: payloads injected into path segments are checked too (AI-074)
        return normalize_text(" ".join(x for x in (req.get("path", ""), req.get("query") or "", req.get("body") or "") if x))

    def _cache_key(self, req):
        digest = hashlib.sha256(f"{req.get('path')}|{req.get('query')}|{req.get('body')}".encode("utf-8", "ignore")).hexdigest()
        return f"{req['method']}|{req['endpoint']}|{digest}"

    def _payload_rules(self, req):
        text = self.payload_text(req)
        hits = []
        for r in self.rules["rules"]:
            k = r["kind"]
            if k == "payload_chars" and any(c in r["chars"] for c in text):
                hits.append(r)
            elif k == "payload_regex" and r["_re"].search(text):
                hits.append(r)
            elif k == "payload_length" and len(text) > self.max_payload_chars:
                hits.append(r)
        return hits

    def check(self, req, rate, now=None):
        now = time.time() if now is None else now
        headers = req.get("headers") or {}
        ua = headers.get("User-Agent", "")
        hits = []
        for r in self.rules["rules"]:
            k = r["kind"]
            if k == "endpoint" and req["endpoint"] not in self.endpoints:
                hits.append((r, {"endpoint": req["endpoint"]}))
            elif k == "ua_missing" and not ua:
                hits.append((r, {}))
            elif k == "ua_regex" and ua and r["_re"].search(ua):
                hits.append((r, {}))
            elif k == "rate" and rate > self.rate_threshold:
                hits.append((r, {"rate": rate, "window": f"{self.rate_window_s:g}"}))
            elif k == "header_bounds" and (len(headers) > r.get("max_headers", 40) or
                                           any(len(str(v)) > r.get("max_header_value_chars", 4096) for v in headers.values())):
                hits.append((r, {}))

        key = self._cache_key(req)
        cached = False
        expiry = self.clean_cache.get(key)
        if expiry and expiry > now:
            cached = True                                   # payload already known clean
        else:
            self.clean_cache.pop(key, None)
            p_hits = self._payload_rules(req)
            hits += [(r, {}) for r in p_hits]
            if not p_hits:
                self.clean_cache[key] = now + self.cache_ttl_s
                if len(self.clean_cache) > self.cache_size:
                    self.clean_cache.popitem(last=False)
        reasons = [r["reason"].format(**ctx) for r, ctx in hits]
        return bool(hits), reasons, [r["id"] for r, _ in hits], cached
