"""Trains all three agents on synthetic traffic and saves them to models/agents.joblib."""
import os
import random
import time

import joblib

from .agents import AnomalyAgent, BehaviorAgent, PayloadAgent
from .traffic import ATTACK_KINDS, attack_request, generate_session, payload_text

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "agents.joblib")


def train_all(seed=7, normal_sessions=900, attacks_per_type=500, verbose=True):
    t0 = time.time()
    rng = random.Random(seed)
    normal, seqs = [], []
    for _ in range(normal_sessions):
        s = generate_session(rng, "normal", 0)
        normal += s
        seqs.append([r["endpoint"] for r in s])
    if verbose:
        print(f"  generated {len(normal)} normal requests from {normal_sessions} sessions")

    anomaly = AnomalyAgent().fit(normal)                      # normal traffic only
    texts = [payload_text(r) for r in normal if payload_text(r)]
    labels = ["normal"] * len(texts)
    for kind in ATTACK_KINDS:                                 # KNOWN attack styles only
        for _ in range(attacks_per_type):
            r = attack_request(rng, kind, False, "u", "0.0.0.0", 0)
            texts.append(payload_text(r))
            labels.append(kind)
    payload = PayloadAgent().fit(texts, labels)
    behavior = BehaviorAgent().fit(seqs)
    if verbose:
        print(f"  trained 3 agents in {time.time() - t0:.1f}s")
    return anomaly, payload, behavior


def load_or_train(force=False):
    if not force and os.path.exists(MODEL_PATH):
        return joblib.load(MODEL_PATH)
    print("Training agents (first run only, about 20 seconds)...")
    agents = train_all()
    os.makedirs(os.path.dirname(MODEL_PATH), exist_ok=True)
    joblib.dump(agents, MODEL_PATH)
    return agents


if __name__ == "__main__":
    load_or_train(force=True)
    print("Saved:", MODEL_PATH)
