"""
AGENT 3: BEHAVIOR ANALYSIS AGENT
Model: LSTM (sequence model)
Analyzes: user behavior over time — endpoint access sequences, session patterns
Output: {behavior_score: 0-1, confidence: 0-1, sequence_anomaly: str}
"""

import numpy as np
import random
import tensorflow as tf
from tensorflow.keras import layers, models

# ---------------------------------------------------------------------------
# 1. ENDPOINT VOCAB + SEQUENCE ENCODING
# ---------------------------------------------------------------------------
ENDPOINTS = [
    "/login", "/home", "/products", "/product_detail", "/cart", "/checkout",
    "/orders", "/profile", "/search", "/logout",
    "/admin", "/admin/users", "/admin/export", "/api/internal/config",
]
ENDPOINT_TO_IDX = {e: i + 1 for i, e in enumerate(ENDPOINTS)}  # 0 = padding
SEQ_LEN = 15  # number of requests per session window


def encode_sequence(endpoints: list, seq_len: int = SEQ_LEN) -> np.ndarray:
    ids = [ENDPOINT_TO_IDX.get(e, 0) for e in endpoints[-seq_len:]]
    ids = [0] * (seq_len - len(ids)) + ids  # left-pad
    return np.array(ids, dtype=np.int32)


# ---------------------------------------------------------------------------
# 2. SYNTHETIC SESSION DATA
#    Normal: realistic shopping journeys.
#    Anomalous: privilege-escalation probing, scraping, endpoint enumeration.
# ---------------------------------------------------------------------------
NORMAL_FLOWS = [
    ["/login", "/home", "/products", "/product_detail", "/cart", "/checkout", "/orders"],
    ["/home", "/search", "/product_detail", "/product_detail", "/cart", "/checkout"],
    ["/login", "/profile", "/orders", "/logout"],
    ["/home", "/products", "/search", "/product_detail", "/cart"],
]

ANOMALOUS_FLOWS = [
    # rapid privilege escalation probing
    ["/login", "/profile", "/admin", "/admin/users", "/admin/export"],
    # endpoint enumeration / scraping — same action many times fast
    ["/product_detail"] * 10,
    # jump straight to admin without normal navigation
    ["/login", "/admin/export", "/api/internal/config"],
    ["/api/internal/config", "/admin/users", "/admin/export"],
]


def _sample_session(flows, min_len=5, max_len=SEQ_LEN):
    base = random.choice(flows)
    # add small random repeats/noise to vary sequences
    seq = list(base)
    while len(seq) < min_len:
        seq.append(random.choice(base))
    return seq[:max_len]


def build_dataset(n_normal=600, n_anomalous=200):
    X, y = [], []
    for _ in range(n_normal):
        X.append(encode_sequence(_sample_session(NORMAL_FLOWS)))
        y.append(0)
    for _ in range(n_anomalous):
        X.append(encode_sequence(_sample_session(ANOMALOUS_FLOWS)))
        y.append(1)
    X, y = np.array(X), np.array(y)
    idx = np.arange(len(X))
    np.random.shuffle(idx)
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# 3. MODEL
# ---------------------------------------------------------------------------
def build_model(vocab_size=len(ENDPOINTS) + 1, seq_len=SEQ_LEN):
    inputs = layers.Input(shape=(seq_len,), dtype="int32")
    x = layers.Embedding(vocab_size, 16, input_length=seq_len, mask_zero=True)(inputs)
    x = layers.LSTM(32, return_sequences=False)(x)
    x = layers.Dense(16, activation="relu")(x)
    x = layers.Dropout(0.2)(x)
    outputs = layers.Dense(1, activation="sigmoid")(x)

    model = models.Model(inputs, outputs)
    model.compile(optimizer="adam", loss="binary_crossentropy", metrics=["accuracy"])
    return model


# ---------------------------------------------------------------------------
# 4. SEQUENCE ANOMALY DESCRIPTION (rule-based explanation layer)
# ---------------------------------------------------------------------------
SENSITIVE_ENDPOINTS = {"/admin", "/admin/users", "/admin/export", "/api/internal/config"}


def describe_sequence_anomaly(endpoints: list) -> str:
    reasons = []
    hit_sensitive = [e for e in endpoints if e in SENSITIVE_ENDPOINTS]
    if hit_sensitive:
        reasons.append(f"accessed sensitive endpoint(s): {', '.join(set(hit_sensitive))}")
    if len(endpoints) >= 5 and len(set(endpoints)) == 1:
        reasons.append("repetitive identical requests (possible scraping/enumeration)")
    if "/login" not in endpoints[:2] and hit_sensitive:
        reasons.append("sensitive access without preceding normal navigation")
    return "; ".join(reasons) if reasons else "session pattern deviates from typical navigation flow"


# ---------------------------------------------------------------------------
# 5. AGENT
# ---------------------------------------------------------------------------
class BehaviorAgent:
    def __init__(self):
        self.model = build_model()
        self.is_fitted = False

    def train(self, X, y, epochs=10, batch_size=32, validation_split=0.15):
        history = self.model.fit(
            X, y, epochs=epochs, batch_size=batch_size,
            validation_split=validation_split, verbose=2,
        )
        self.is_fitted = True
        return history

    def predict(self, session_endpoints: list) -> dict:
        if not self.is_fitted:
            raise RuntimeError("Call train() first.")
        vec = encode_sequence(session_endpoints).reshape(1, -1)
        score = float(self.model.predict(vec, verbose=0)[0][0])
        confidence = abs(score - 0.5) * 2  # distance from indecision (0.5) scaled to 0-1

        return {
            "agent": "behavior",
            "behavior_score": round(score, 4),
            "confidence": round(confidence, 4),
            "sequence_anomaly": describe_sequence_anomaly(session_endpoints) if score > 0.5 else "normal navigation pattern",
        }

    def save(self, path="behavior_agent.keras"):
        self.model.save(path)

    def load(self, path="behavior_agent.keras"):
        self.model = tf.keras.models.load_model(path)
        self.is_fitted = True


# ---------------------------------------------------------------------------
# 6. DEMO
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    X, y = build_dataset(n_normal=500, n_anomalous=200)
    split = int(len(X) * 0.85)
    X_train, y_train = X[:split], y[:split]
    X_test, y_test = X[split:], y[split:]

    agent = BehaviorAgent()
    agent.train(X_train, y_train, epochs=10)

    loss, acc = agent.model.evaluate(X_test, y_test, verbose=0)
    print(f"\nHeld-out test accuracy: {acc:.2%} (synthetic data — inflated vs. real traffic)")

    agent.save()

    print("\n=== Normal shopping session ===")
    print(agent.predict(["/login", "/home", "/products", "/product_detail", "/cart", "/checkout"]))

    print("\n=== Privilege escalation probing ===")
    print(agent.predict(["/login", "/profile", "/admin", "/admin/users", "/admin/export"]))

    print("\n=== Scraping/enumeration pattern ===")
    print(agent.predict(["/product_detail"] * 10))
