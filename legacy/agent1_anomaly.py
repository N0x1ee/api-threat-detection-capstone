"""
AGENT 1: ANOMALY DETECTION AGENT
Model: Isolation Forest
Analyzes: statistical patterns — request length, header entropy, character ratios,
          special-char ratio, digit ratio, param count
Output: {anomaly_score: 0-1, confidence: 0-1, reason: str}
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import Counter
import math
import random
import string
import joblib


# ---------------------------------------------------------------------------
# 1. FEATURE EXTRACTION
# ---------------------------------------------------------------------------
def shannon_entropy(s: str) -> float:
    """Higher entropy = more random-looking string (often obfuscated payload)."""
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_features(request: dict) -> dict:
    """
    request = {
        "path": "/api/users?id=1",
        "headers": {"User-Agent": "...", "Content-Type": "..."},
        "body": "...",
        "method": "GET",
    }
    """
    path = request.get("path", "")
    body = request.get("body", "") or ""
    headers = request.get("headers", {}) or {}
    full_payload = path + " " + body

    length = len(full_payload)
    special_chars = sum(1 for c in full_payload if c in "!@#$%^&*()<>{}[]|;'\"=+")
    digits = sum(1 for c in full_payload if c.isdigit())
    header_blob = " ".join(f"{k}:{v}" for k, v in headers.items())

    return {
        "length": length,
        "entropy": shannon_entropy(full_payload),
        "header_entropy": shannon_entropy(header_blob),
        "special_char_ratio": special_chars / max(length, 1),
        "digit_ratio": digits / max(length, 1),
        "param_count": path.count("&") + path.count("="),
        "num_headers": len(headers),
        "path_depth": path.count("/"),
    }


FEATURE_ORDER = [
    "length", "entropy", "header_entropy", "special_char_ratio",
    "digit_ratio", "param_count", "num_headers", "path_depth",
]


def features_to_vector(feat: dict) -> np.ndarray:
    return np.array([feat[k] for k in FEATURE_ORDER], dtype=float)


# ---------------------------------------------------------------------------
# 2. SYNTHETIC DATA (stand-in until you plug in real traffic logs / a public
#    dataset like CSE-CIC-IDS2018 or your own Juice Shop captured traffic)
# ---------------------------------------------------------------------------
def make_normal_request():
    paths = ["/api/users/42", "/api/products?category=shoes", "/api/orders/17",
             "/api/cart", "/api/search?q=laptop"]
    return {
        "path": random.choice(paths),
        "headers": {"User-Agent": "Mozilla/5.0", "Content-Type": "application/json"},
        "body": random.choice(["", '{"qty":1}', '{"name":"John"}']),
        "method": random.choice(["GET", "POST"]),
    }


def make_anomalous_request():
    junk = "".join(random.choices(string.ascii_letters + string.digits + "!@#$%^&*();", k=random.randint(80, 300)))
    return {
        "path": f"/api/users?id=1' OR '1'='1{junk[:40]}",
        "headers": {"User-Agent": junk[:30], "X-Forwarded-For": junk[:20]},
        "body": junk,
        "method": "POST",
    }


def build_dataset(n_normal=2000, n_anomalous=200):
    rows = []
    for _ in range(n_normal):
        rows.append(features_to_vector(extract_features(make_normal_request())))
    for _ in range(n_anomalous):
        rows.append(features_to_vector(extract_features(make_anomalous_request())))
    X = np.vstack(rows)
    y = np.array([0] * n_normal + [1] * n_anomalous)  # 1 = anomaly (only for eval, unsupervised training doesn't use this)
    return X, y


# ---------------------------------------------------------------------------
# 3. AGENT
# ---------------------------------------------------------------------------
class AnomalyAgent:
    def __init__(self, contamination: float = 0.1):
        self.scaler = StandardScaler()
        self.model = IsolationForest(
            n_estimators=200,
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.is_fitted = False

    def train(self, X: np.ndarray):
        Xs = self.scaler.fit_transform(X)
        self.model.fit(Xs)
        # calibrate scaling using the training distribution of raw scores
        raw_scores = self.model.decision_function(Xs)
        self._raw_min = float(raw_scores.min())
        self._raw_max = float(raw_scores.max())
        self.is_fitted = True

    def _reason(self, feat: dict) -> str:
        reasons = []
        if feat["entropy"] > 4.5:
            reasons.append("unusually high payload randomness (possible obfuscation)")
        if feat["special_char_ratio"] > 0.15:
            reasons.append("high ratio of special characters")
        if feat["length"] > 200:
            reasons.append("abnormally long request")
        if feat["param_count"] > 5:
            reasons.append("excessive query parameters")
        return "; ".join(reasons) if reasons else "statistical deviation from normal traffic baseline"

    def predict(self, request: dict) -> dict:
        if not self.is_fitted:
            raise RuntimeError("Call train() first.")
        feat = extract_features(request)
        vec = features_to_vector(feat).reshape(1, -1)
        vec_s = self.scaler.transform(vec)

        # decision_function: higher = more normal, lower/negative = more anomalous.
        raw_score = self.model.decision_function(vec_s)[0]

        # normalize using the training distribution's range, clipped to [0,1],
        # then invert so higher = more anomalous
        span = max(self._raw_max - self._raw_min, 1e-6)
        normalized = (raw_score - self._raw_min) / span
        normalized = min(max(normalized, 0.0), 1.0)
        anomaly_score = 1.0 - normalized

        # confidence = distance from the decision boundary (0), scaled by training spread
        confidence = min(abs(raw_score) / (span / 2), 1.0)

        return {
            "agent": "anomaly",
            "anomaly_score": round(float(anomaly_score), 4),
            "confidence": round(float(confidence), 4),
            "reason": self._reason(feat),
        }

    def save(self, path="anomaly_agent.joblib"):
        joblib.dump({"model": self.model, "scaler": self.scaler}, path)

    def load(self, path="anomaly_agent.joblib"):
        d = joblib.load(path)
        self.model, self.scaler = d["model"], d["scaler"]
        self.is_fitted = True


# ---------------------------------------------------------------------------
# 4. DEMO
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    X, y = build_dataset()
    agent = AnomalyAgent(contamination=0.1)
    agent.train(X)
    agent.save()

    print("=== Normal request ===")
    print(agent.predict(make_normal_request()))

    print("\n=== Anomalous request ===")
    print(agent.predict(make_anomalous_request()))

    # quick sanity check against synthetic labels
    correct = 0
    for i in range(len(X)):
        raw = agent.model.decision_function(agent.scaler.transform(X[i].reshape(1, -1)))[0]
        pred = 1 if raw < 0 else 0
        correct += (pred == y[i])
    print(f"\nSynthetic-data self-check accuracy: {correct/len(X):.2%} (sanity check only, not a real benchmark)")
