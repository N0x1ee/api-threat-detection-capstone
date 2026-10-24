"""Loads and validates config.json (SRS v1.1 FR-085, FR-086, FR-043).

Usage:  from app.config import load_config;  cfg = load_config()
A bad value raises ConfigError naming the parameter, and the app does not start.
"""
import copy
import json
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PATH = os.path.join(ROOT, "config.json")
AGENT_NAMES = ("anomaly", "payload", "behavior")

DEFAULTS = {
    "thresholds": {"allow_below": 0.3, "block_above": 0.7},
    "aggregation": {"mode": "A", "vote_threshold": 0.5, "epsilon": 1e-6},
    "weights": {"initial": 1.0, "min": 0.1, "max": 2.0, "alpha": 0.3, "max_delta": 0.2,
                "update_every": 1000, "window": 1000, "min_positives": 30,
                "use_analyst_labels": True, "frozen": False},
    "agents": {"timeout_ms": 150, "disabled": [], "failure_policy": "fail_open_flag",
               "models": {"anomaly": "isolation_forest", "payload": "ngram", "behavior": "lstm"}},
    "fast_filter": {"rules_file": "rules/fast_filter.json", "rate_window_s": 10, "rate_threshold": 8,
                    "max_payload_chars": 400, "cache_ttl_s": 60},
    "audit": {"async_writes": True, "queue_size": 10000},
    "gateway": {"upstream": "http://127.0.0.1:8001", "start_demo_api": True, "demo_api_port": 8001,
                "upstream_timeout_s": 5, "trusted_proxy": False,
                "rate_limit": {"max_requests": 60, "window_s": 10}, "max_inspect_bytes": 65536},
    "auth": {"session_idle_minutes": 30, "session_max_hours": 12, "cookie_secure": False,
             "max_failed_logins": 5, "lockout_minutes": 5, "min_password_length": 8},
}


class ConfigError(ValueError):
    pass


def _merge(base, extra):
    out = copy.deepcopy(base)
    for k, v in (extra or {}).items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


def _num(cfg, section, key, lo=None, hi=None, integer=False, lo_open=False, hi_open=False):
    v = cfg[section][key]
    name = f"{section}.{key}"
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        raise ConfigError(f"{name} must be a number, got {v!r}")
    if integer and int(v) != v:
        raise ConfigError(f"{name} must be a whole number, got {v!r}")
    if lo is not None and (v <= lo if lo_open else v < lo):
        raise ConfigError(f"{name} = {v} is below its allowed minimum {lo}")
    if hi is not None and (v >= hi if hi_open else v > hi):
        raise ConfigError(f"{name} = {v} is above its allowed maximum {hi}")
    return v


def validate(cfg):
    t1 = _num(cfg, "thresholds", "allow_below", 0, 1, lo_open=True, hi_open=True)
    t2 = _num(cfg, "thresholds", "block_above", 0, 1, lo_open=True, hi_open=True)
    if not t1 < t2:
        raise ConfigError(f"thresholds.allow_below ({t1}) must be smaller than thresholds.block_above ({t2})")
    if cfg["aggregation"]["mode"] not in ("A", "B", "C", "D"):
        raise ConfigError(f"aggregation.mode must be A, B, C or D, got {cfg['aggregation']['mode']!r}")
    _num(cfg, "aggregation", "vote_threshold", 0, 1)
    _num(cfg, "aggregation", "epsilon", 0, 1, lo_open=True)
    wmin = _num(cfg, "weights", "min", 0, lo_open=True)
    wmax = _num(cfg, "weights", "max", wmin)
    _num(cfg, "weights", "initial", wmin, wmax)
    _num(cfg, "weights", "alpha", 0, 1, lo_open=True)
    _num(cfg, "weights", "max_delta", 0, lo_open=True)
    _num(cfg, "weights", "update_every", 1, integer=True)
    _num(cfg, "weights", "window", 1, integer=True)
    _num(cfg, "weights", "min_positives", 0, integer=True)
    _num(cfg, "agents", "timeout_ms", 1)
    bad = [a for a in cfg["agents"]["disabled"] if a not in AGENT_NAMES]
    if bad:
        raise ConfigError(f"agents.disabled has unknown agent(s) {bad}; valid: {list(AGENT_NAMES)}")
    models = cfg["agents"].get("models", {})
    allowed = {"anomaly": ("isolation_forest",), "payload": ("ngram", "cnn"), "behavior": ("markov", "lstm")}
    for agent, model in models.items():
        if agent not in allowed or model not in allowed[agent]:
            raise ConfigError(f"agents.models.{agent} = {model!r} is not valid; options: {allowed.get(agent)}")
    if cfg["agents"]["failure_policy"] not in ("fail_open_flag", "fail_closed"):
        raise ConfigError("agents.failure_policy must be fail_open_flag or fail_closed")
    _num(cfg, "fast_filter", "rate_window_s", 0, lo_open=True)
    _num(cfg, "fast_filter", "rate_threshold", 1, integer=True)
    _num(cfg, "fast_filter", "max_payload_chars", 1, integer=True)
    _num(cfg, "fast_filter", "cache_ttl_s", 0)
    if not isinstance(cfg["fast_filter"]["rules_file"], str) or not cfg["fast_filter"]["rules_file"]:
        raise ConfigError("fast_filter.rules_file must be a path to the rules JSON file")
    if not isinstance(cfg["audit"]["async_writes"], bool):
        raise ConfigError("audit.async_writes must be true or false")
    _num(cfg, "audit", "queue_size", 1, integer=True)
    g = cfg["gateway"]
    if not str(g["upstream"]).startswith(("http://", "https://")):
        raise ConfigError(f"gateway.upstream must start with http:// or https://, got {g['upstream']!r}")
    _num(cfg, "gateway", "demo_api_port", 1, 65535, integer=True)
    _num(cfg, "gateway", "upstream_timeout_s", 0, lo_open=True)
    _num(cfg, "gateway", "max_inspect_bytes", 1, integer=True)
    rl = g["rate_limit"]
    for k in ("max_requests", "window_s"):
        v = rl.get(k)
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v <= 0:
            raise ConfigError(f"gateway.rate_limit.{k} must be a positive number, got {v!r}")
    _num(cfg, "auth", "session_idle_minutes", 0, lo_open=True)
    _num(cfg, "auth", "session_max_hours", 0, lo_open=True)
    _num(cfg, "auth", "max_failed_logins", 1, integer=True)
    _num(cfg, "auth", "lockout_minutes", 0, lo_open=True)
    _num(cfg, "auth", "min_password_length", 8, integer=True)
    if not isinstance(cfg["auth"]["cookie_secure"], bool):
        raise ConfigError("auth.cookie_secure must be true or false")
    return cfg


def load_config(path=None, overrides=None):
    """Defaults <- config.json <- overrides (a dict, used by tests and evaluate.py)."""
    path = path or os.environ.get("APP_CONFIG", DEFAULT_PATH)
    data = {}
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                raise ConfigError(f"{path} is not valid JSON: {e}") from None
    return validate(_merge(_merge(DEFAULTS, data), overrides))
