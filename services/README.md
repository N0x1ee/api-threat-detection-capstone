# Services — proposal architecture

Read `ARCHITECTURE.md` first: it has the flow, Kafka topics, JSON messages and Redis keys.

## Run everything (Docker)

1. Put a `.env` file in `C:\capstone` that contains `ADMIN_USERNAME=admin` and `ADMIN_PASSWORD=<at least 8 characters>`.
2. From `C:\capstone`, run `docker compose up --build`. The first build takes a few minutes.
3. Send traffic through the gateway at http://localhost:8080, for example http://localhost:8080/products or http://localhost:8080/search?q=x%27%20OR%201=1--.
4. Watch the dashboard at http://localhost:3000.

## Run without Docker or Kafka (development)

Set `BUS=redis`. This runs the same topics and JSON over Redis Streams, and needs only Redis and PostgreSQL (database `threats`, user `capstone`).

| What | Command (from `services/`) | Port |
|---|---|---|
| Decision engine | `cd decision-engine` then `go run .` | 7003 |
| Fast filter | `python fastfilter/service.py` | 7001 |
| Agents | `AGENT=anomaly python agents/worker.py`, then the same with `payload` and `behavior` | – |
| XAI + dashboard API | `ADMIN_USERNAME=admin ADMIN_PASSWORD=... python xai/service.py` | 7002 |
| Dashboard | `cd dashboard`, then `npm install`, then `npm run dev` | 3000 |
| Gateway stand-in | `python tools/gateway_sim.py` | – |

Also set `CONFIG=../api-threat-detection/config.json`.

## Status

| Service | Built | Tested |
|---|---|---|
| Decision engine (Go) | yes | 11 unit tests, and end to end on the Redis bus |
| Fast filter, agents, XAI/dashboard API (Python) | yes | end to end on the Redis bus with PostgreSQL |
| Dashboard (React) | yes | login, feed, detail and review checked in a browser |
| Gateway (Spring Boot) | yes | **not compiled yet.** Maven Central was blocked where it was written, so it needs `mvn package` on a real machine |
| Kafka path | yes | **not run yet.** No broker was available, so the first `docker compose up` is its test |
