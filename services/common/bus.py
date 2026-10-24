"""Message bus for the Python services: Kafka (BUS=kafka, default) or Redis Streams (BUS=redis).

Same topic names and JSON payloads as the Go decision engine (see services/ARCHITECTURE.md).
"""
import json
import logging
import os
import threading
import time

log = logging.getLogger("bus")


def _redis():
    import redis
    return redis.Redis.from_url(os.environ.get("REDIS_URL", "redis://localhost:6379/0"), decode_responses=True)


class KafkaBus:
    def __init__(self, brokers=None):
        from confluent_kafka import Producer
        self.brokers = brokers or os.environ.get("KAFKA_BROKERS", "localhost:9092")
        self.producer = Producer({"bootstrap.servers": self.brokers, "linger.ms": 1, "acks": 1})

    def publish(self, topic, key, value):
        self.producer.produce(topic, key=(key or "").encode(), value=json.dumps(value, default=str).encode())
        self.producer.poll(0)

    def flush(self, timeout=5):
        self.producer.flush(timeout)

    def subscribe(self, topics, group, handler, stop=None):
        from confluent_kafka import Consumer

        def run():
            c = Consumer({"bootstrap.servers": self.brokers, "group.id": group, "auto.offset.reset": "latest",
                          "enable.auto.commit": True, "fetch.wait.max.ms": 5, "allow.auto.create.topics": True})
            c.subscribe(list(topics))
            try:
                while not (stop and stop.is_set()):
                    m = c.poll(0.05)
                    if m is None:
                        continue
                    if m.error():
                        log.warning("kafka %s: %s", m.topic(), m.error())
                        continue
                    _dispatch(handler, m.topic(), m.value())
            finally:
                c.close()

        t = threading.Thread(target=run, daemon=True, name=f"kafka-{group}")
        t.start()
        return t


class RedisBus:
    def __init__(self, client=None):
        self.r = client or _redis()

    def publish(self, topic, key, value):
        self.r.xadd(f"bus:{topic}", {"key": key or "", "value": json.dumps(value, default=str)},
                    maxlen=100000, approximate=True)

    def flush(self, timeout=5):
        pass

    def subscribe(self, topics, group, handler, stop=None):
        import redis
        streams = {f"bus:{t}": ">" for t in topics}
        for s in streams:
            try:
                self.r.xgroup_create(s, group, id="$", mkstream=True)
            except redis.ResponseError as e:
                if "BUSYGROUP" not in str(e):
                    raise

        def run():
            while not (stop and stop.is_set()):
                try:
                    res = self.r.xreadgroup(group, f"{group}-1", streams, count=100, block=50)
                except Exception as e:                     # Redis restarting etc.
                    log.warning("redis bus: %s", e)
                    time.sleep(0.5)
                    continue
                for stream, msgs in res or []:
                    for mid, fields in msgs:
                        _dispatch(handler, stream[4:], fields.get("value", "{}"))
                        self.r.xack(stream, group, mid)

        t = threading.Thread(target=run, daemon=True, name=f"redis-{group}")
        t.start()
        return t


def _dispatch(handler, topic, raw):
    try:
        msg = json.loads(raw)
    except (TypeError, ValueError):
        log.warning("dropping non-JSON message on %s", topic)
        return
    try:
        handler(topic, msg)
    except Exception:
        log.exception("handler failed on %s", topic)


def make_bus():
    return RedisBus() if os.environ.get("BUS", "kafka") == "redis" else KafkaBus()
