"""Agent worker: one process per agent (AGENT=anomaly|payload|behavior).

Consumes Kafka `requests.suspicious`, runs its model, publishes to `agent.results`.
Each agent uses its own consumer group, so every agent sees every request.
The models are the ones trained by api-threat-detection (app/training.py); swapping in the
CNN / LSTM later only changes load_agent().
"""
import logging
import os
import signal
import sys
import threading
import time

ROOT = os.environ.get("APP_ROOT", os.path.join(os.path.dirname(__file__), "..", "..", "api-threat-detection"))
sys.path.insert(0, os.path.abspath(ROOT))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import numpy as np  # noqa: E402

from common.bus import make_bus  # noqa: E402

log = logging.getLogger("agent")
INDEX = {"anomaly": 0, "payload": 1, "behavior": 2}


def clean(o):
    """Make agent detail JSON-safe (numpy types, tuples)."""
    if isinstance(o, dict):
        return {str(k): clean(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [clean(v) for v in o]
    if isinstance(o, np.generic):
        return o.item()
    if isinstance(o, float) and not np.isfinite(o):
        return None
    return o


def load_agent(name):
    """Primary or baseline model per config.json agents.models (AI-071, AI-072)."""
    from app.config import load_config
    choice = load_config(os.environ.get("CONFIG")).get("agents", {}).get("models", {}).get(name)
    weights = os.path.join(os.path.abspath(ROOT), "weights")
    if name == "behavior" and choice == "lstm":
        from app.behavior_lstm import LSTMBehaviorAgent
        return LSTMBehaviorAgent(os.path.join(weights, "behavior_lstm.npz"))
    if name == "payload" and choice == "cnn":
        from app.cnn_payload import CNNPayloadAgent
        return CNNPayloadAgent(os.path.join(weights, "payload_cnn.npz"))
    from app.training import load_or_train
    return load_or_train()[INDEX[name]]


def model_tag(name, agent):
    v = getattr(agent, "feature_version", None)
    return getattr(agent, "model_name", None) or (f"{type(agent).__name__}" + (f"@v{v}" if v else ""))


def handle(name, agent, ev):
    """Runs one agent on one RequestEvent. Returns the agent.results message."""
    t0 = time.perf_counter()
    out = {"request_id": ev.get("request_id"), "agent": name, "model": model_tag(name, agent),
           "score": None, "confidence": None, "detail": {}, "error": None}
    try:
        if name == "behavior":
            history = list(ev.get("history") or [])
            rate = (ev.get("fast_filter") or {}).get("rate", len(history))
            if getattr(agent, "model_name", "") != "lstm":      # Markov baseline wants endpoint strings
                history = [h.get("e", "") if isinstance(h, dict) else h for h in history]
            res = agent.analyze(history, rate)
        else:
            req = {k: ev.get(k) for k in ("method", "path", "query", "body", "headers", "ip")}
            req["endpoint"] = ev.get("endpoint") or req.get("path") or "/"
            res = agent.analyze(req)
        out.update(score=float(res.score), confidence=float(res.confidence), detail=clean(res.detail or {}))
    except Exception as e:                       # reported, so the engine excludes this agent (FR-034)
        log.exception("agent %s failed on %s", name, ev.get("request_id"))
        out["error"] = f"{type(e).__name__}: {e}"
    out["latency_ms"] = round((time.perf_counter() - t0) * 1000, 3)
    return out


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
    name = os.environ.get("AGENT", "")
    if name not in INDEX:
        sys.exit(f"AGENT must be one of {sorted(INDEX)}")
    agent = load_agent(name)
    handle(name, agent, {"request_id": "warmup", "method": "GET", "path": "/", "headers": {}, "history": []})
    bus = make_bus()
    stop = threading.Event()

    def on_request(topic, ev):
        bus.publish("agent.results", ev.get("request_id"), handle(name, agent, ev))

    bus.subscribe(["requests.suspicious"], f"agent-{name}", on_request, stop)
    log.info("%s agent up (%s)", name, model_tag(name, agent))
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        while not stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    bus.flush()


if __name__ == "__main__":
    main()
