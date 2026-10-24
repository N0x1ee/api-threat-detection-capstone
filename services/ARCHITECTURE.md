# Architecture v2 — the proposal stack

This follows the component table in the original proposal, which the guide has asked us to build as written.
The Python monolith in `api-threat-detection/` stays as the reference implementation, and its agent, rule and explanation code is reused here.

```
client ──► API Gateway (Spring Boot :8080)
             │ 1. identity + rate limit (Redis)          ──► 429
             │ 2. POST /check ─► Fast Filter (Python :7001, Redis)
             │       cleared ─► forward to protected API, publish ALLOW to `decisions`
             │       referred ─▼
             │ 3. publish RequestEvent to Kafka `requests.suspicious`
             │ 4. BLPOP Redis `verdict:<request_id>` (timeout = verdict_timeout_ms)
             │       ALLOW/FLAG ─► forward      BLOCK ─► 403      timeout ─► failure policy
             ▼
Kafka `requests.suspicious` ──► Anomaly agent ─┐
                            ──► Payload agent ─┼─► `agent.results` ──► Decision Engine (Go)
                            ──► Behaviour agent┘                         │ aggregate (mode A/B/C)
                                                                         │ RPUSH verdict:<id>  (gateway wakes)
                                                                         ▼
                                                                   `decisions` ──► XAI Generator (Python)
                                                                                     │ explanation
                                                                                     ▼
                                                                               PostgreSQL ◄── Dashboard API ◄── React dashboard
analyst review (dashboard) ──► `labels` ──► Decision Engine (adaptive weights) ──► `weights.updates` ──► PostgreSQL
```

The protected API answers in real time, while Kafka is asynchronous.
The gateway bridges the two: it publishes to Kafka, then waits on one Redis key that the decision engine pushes the verdict to.
If nothing arrives within `verdict_timeout_ms` (default 400 ms), the failure policy applies.
The default policy, `fail_open_flag`, forwards the request and records it as FLAG.

## Services

| Service | Dir | Tech | Owner |
|---|---|---|---|
| API Gateway | `gateway/` | Spring Boot 3, Java 17+ | Navjot |
| Fast Filter | `fastfilter/` | Python, Flask, Redis | AI team |
| Anomaly / Payload / Behaviour agents | `agents/` (one image, `AGENT=` env) | Python, Kafka consumer | AI team (CNN = Sehaj, LSTM = NOxiee) |
| Decision Engine | `decision-engine/` | Go | AI team |
| XAI Generator + Dashboard API | `xai/` | Python, Flask, PostgreSQL | AI team |
| Dashboard | `dashboard/` | React (Vite) | Navjot |
| Kafka, Redis, PostgreSQL | `docker-compose.yml` | containers | — |

## Kafka topics

All messages are JSON (UTF-8), and the key is `request_id`.

### `requests.suspicious` — Gateway → agents, decision engine
```json
{
  "request_id": "32 hex chars", "ts": 1729700000.123,
  "method": "GET", "path": "/search", "query": "q=x", "body": "",
  "headers": {"User-Agent": "..."},
  "ip": "1.2.3.4", "identity": "sha256 digest", "identity_source": "session_cookie|bearer_token|api_key|source_ip",
  "fast_filter": {"reasons": ["..."], "rule_ids": ["R03"], "rules_version": "1.2", "rate": 4},
  "history": ["/login", "/search"],
  "deadline_ms": 150
}
```
`history` is the identity's recent endpoints (newest last). The fast filter keeps this list in Redis and returns it to the gateway with the check result.

### `agent.results` — each agent → decision engine
```json
{"request_id": "...", "agent": "anomaly|payload|behavior", "score": 0.82, "confidence": 0.64,
 "detail": {"reason": "...", "attack_type": "sqli", "top_features": []},
 "latency_ms": 3.1, "model": "isolation_forest@v3", "error": null}
```
If an agent fails, it still publishes, with `"error": "message"` and no score. The engine then excludes it, just as it would for a timeout.

### `decisions` — decision engine (and gateway for cleared requests) → XAI / audit
```json
{"request_id": "...", "ts": 0, "route": "ai|fast_filter|rate_limit", "verdict": "ALLOW|FLAG|BLOCK",
 "score": 0.74, "mode": "A", "thresholds": {"allow_below": 0.3, "block_above": 0.7},
 "agents": {"payload": {"score": 0.9, "confidence": 0.8, "weight": 1.0, "detail": {}}},
 "excluded": {"behavior": "timed out after 150 ms"}, "degraded": true, "policy_used": null,
 "numerator": 0.72, "denominator": 0.8, "contributions": {"payload": 0.72},
 "request": { "...RequestEvent fields..." },
 "timings_ms": {"agents": 12.0, "aggregation": 0.02}}
```

### `labels` — dashboard API → decision engine
`{"request_id": "...", "label": 1, "provenance": "analyst", "scores": {"anomaly": 0.2, "payload": 0.9, "behavior": 0.1}}`

### `weights.updates` — decision engine → XAI / audit
`{"ts": 0, "old": {}, "new": {}, "window": 1000, "positives": 40, "skipped": false, "mcc": {}, "provenance": {}}`

## Redis keys

| Key | Type | Written by | Purpose |
|---|---|---|---|
| `rl:<identity>:<window_start>` | counter, TTL = window | gateway | rate limit (429) |
| `ff:rate:<identity>` | sorted set of timestamps | fast filter | request rate for fast-filter rule and behaviour agent |
| `ff:hist:<identity>` | list, capped at 60 | fast filter | endpoint history |
| `ff:cache:<key>` | string, TTL = cache_ttl_s | fast filter | decision cache (FR-022 to FR-024) |
| `verdict:<request_id>` | list, TTL 30 s | decision engine | wakes the waiting gateway thread |
| `weights` | hash | decision engine | current agent weights (survive restarts) |
| `session:<token>` | hash, TTL = idle timeout | dashboard API | analyst sessions |

## PostgreSQL

Tables: `decisions`, `adjudications`, `weight_updates`, `users`, `auth_events`. The schema is in `xai/schema.sql`, and the XAI service creates it on start.

## Ports

| Service | Port |
|---|---|
| gateway | 8080 (public) |
| dashboard | 3000 (public) |
| fast filter | 7001 |
| dashboard API | 7002 |
| demo protected API | 8001 |
| Kafka | 9092 |
| Redis | 6379 |
| PostgreSQL | 5432 |

## Running

Run `docker compose up --build` from `C:\capstone`.
For development without Kafka, every Python and Go service also accepts `BUS=redis`. That setting uses Redis Streams with the same topic names and JSON, which is how the pipeline is tested where no Kafka broker is available.
