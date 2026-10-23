"""Turns rows of data/processed/srbh_clean.csv.gz into the request dicts the agents use."""
import math
import os

import pandas as pd

from .traffic import normalize_endpoint

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_PATH = os.path.join(ROOT, "data", "processed", "srbh_clean.csv.gz")

# CSV column -> HTTP header name. Only headers SR-BH actually recorded.
HEADER_COLS = {"user_agent": "User-Agent", "referer": "Referer", "host": "Host", "origin": "Origin",
               "cookie_hash": "Cookie", "content_type": "Content-Type", "accept": "Accept",
               "accept_language": "Accept-Language", "accept_encoding": "Accept-Encoding",
               "dnt": "DNT", "connection": "Connection"}


def _s(v):
    return "" if v is None or (isinstance(v, float) and math.isnan(v)) else str(v)


def to_request(row):
    path = _s(row.get("path")) or "/"
    headers = {h: _s(row.get(c)) for c, h in HEADER_COLS.items() if _s(row.get(c))}
    return {"method": _s(row.get("method")) or "GET", "path": path, "endpoint": normalize_endpoint(path),
            "query": _s(row.get("query")), "body": _s(row.get("body")), "headers": headers,
            "ip": _s(row.get("src_net_hash")), "user": _s(row.get("identity")), "ts": 0.0,
            "label": _s(row.get("label")), "is_attack": int(row.get("is_attack") or 0)}


def load(path=DEFAULT_PATH, splits=("train", "val", "test")):
    """Returns {split: [request, ...]}, each list in capture order."""
    if not os.path.exists(path):
        raise FileNotFoundError(f"{path} not found. Run data/prepare_srbh.py first (see data/README.md).")
    df = pd.read_csv(path, low_memory=False)
    out = {}
    for sp in splits:
        part = df[df["split"] == sp].sort_values("id")
        out[sp] = [to_request(r) for r in part.to_dict("records")]
    return out
