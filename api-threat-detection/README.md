# Adaptive Multi-Agent & Explainable AI System for Real-Time API Threat Detection

MCA major project. Runs on one laptop. No Kafka and no internet needed; Docker is optional.

## Run it (2 minutes)

```
pip install -r requirements.txt
python run.py
```

Your browser opens at http://localhost:8000. The first run trains the three agents (a few seconds).
Evaluation: `python evaluate.py` (1–2 minutes). Writes `results/evaluation.md`, `results/evaluation.json` and, if matplotlib is installed, `results/reliability.png`.

Tests: `python -m unittest discover -s tests -t .` (58 tests, under 10 seconds; password hashing is slow on purpose).

## Configuration

Every tunable number is in `config.json`: thresholds, aggregation mode (A/B/C), weight settings, agent timeout, disabled agents, failure policy and fast-filter limits. The app checks the file at startup and refuses to start on a bad value, naming it (for example `thresholds.allow_below (0.7) must be smaller than thresholds.block_above (0.3)`). Use another file with `APP_CONFIG=path/to/file.json`.

## Gateway and demo API

`python run.py` starts two things: the System on port 8000 (dashboard + gateway) and a small **demo shop API** on `127.0.0.1:8001`, which the gateway protects. Send traffic to `http://localhost:8000/gateway/<path>`:

- **ALLOW and FLAG** are forwarded to the shop API, and its real response is returned. FLAG also goes to the review queue.
- **BLOCK** returns `403 {"error": "request blocked", "request_id": ...}`. Nothing is forwarded, and no score, rule or explanation is revealed.
- **Too many requests** from one identity (default 60 per 10 s, `gateway.rate_limit`) returns `429`, and the rejection is still recorded.
- **Every response** carries `X-Request-ID`, the same ID stored with the decision, so a client report can be matched to the dashboard.
- **Identity** is the session cookie, bearer token or API key (stored only as hashes), otherwise the source IP. `X-User-Id` and `X-Forwarded-For` sent by a client are **ignored**, so an attacker cannot reset their history by changing a header. Set `gateway.trusted_proxy` to `true` only behind a proxy you control.
- **If the shop API is down**, the gateway returns `502`.

## Login

The dashboard needs an account. Nothing is built in (no default passwords).

- **First start:** `python run.py` asks you to create the first **administrator** (username + password, at least 8 characters).
- **More accounts:** `python manage_users.py add sehaj` (analyst) or `python manage_users.py add shrey --role admin`. Also available: `passwd`, `disable`, `list`, `events` (last 50 login attempts).
- **Without a terminal** (Docker, scripts): set `ADMIN_USERNAME` / `ADMIN_PASSWORD` (and optionally `ANALYST_USERNAME` / `ANALYST_PASSWORD`) before starting.

| | Analyst | Administrator |
|---|---|---|
| Dashboard, simulator, try-a-request, review queue | ✓ | ✓ |
| Reset demo, view login history, list users | – | ✓ |

How it is protected (SRS Section 8):

- Passwords are stored only as salted scrypt hashes.
- Sessions live on the server. The cookie is `HttpOnly` and `SameSite=Strict`, sessions end after 30 minutes idle (12 hours at most), and changing a password ends that user's sessions.
- Every state-changing request needs the session's CSRF token.
- 5 failed logins lock that username + IP for 5 minutes.
- Every login attempt and logout is recorded (`manage_users.py events`).
- Overrides record which analyst made them.
- `/gateway/*` and `/health` stay public: they are the protected API's own traffic.
- Settings are under `auth` in `config.json`. Set `cookie_secure` to `true` once the dashboard runs over HTTPS.

## Docker

```
set ADMIN_USERNAME=yourname
set ADMIN_PASSWORD=a-long-password
docker compose up --build
```

(On Linux or macOS use `export` instead of `set`, or put both values in a `.env` file next to `docker-compose.yml`. Do not commit that file.)

This runs two containers: `system` (published on port 8000) and `demo-api` (internal only, not reachable from the host). The audit database and trained models live in named volumes, so they survive restarts. Note: the compose file has not been tested end-to-end yet, because Docker Hub was not reachable from the machine it was written on. The same two-process setup was tested without Docker.

## 5-minute demo script

1. Click **Mixed traffic (with zero-day)**. Watch the counters, charts and decision table fill up.
2. Click a **BLOCK** row. Show the plain-English reason, the suspicious parts of the payload, and each agent's score, confidence and weight.
3. In **Try one request**, pick *Normal search* (cleared by the fast filter in about 1 ms), then *SQL injection, obfuscated* (caught although never seen in training). *Normal, but contains an apostrophe* scores low but may land in FLAG. Be ready to explain that: the fast filter is cautious about apostrophes, and the agents decide.
4. Pick *Probe of a hidden admin page*. Only the **behavior** agent sees this one. This shows why confidence-weighted voting beats simple majority voting.
5. Use the **Review queue** to allow or block flagged requests. Those clicks feed the adaptive weights.
6. Show the real gateway: `curl -i "http://localhost:8000/gateway/products"` is forwarded to the demo shop API and returns its JSON. `curl -i "http://localhost:8000/gateway/search?q=%27+OR+1%3D1--"` returns **403** with only an error and a request ID. The attacker learns nothing about scores or rules, and the request never reaches the shop API (check `demo_api/access.log`). The explanation is on the dashboard, under the same request ID.

## How the code maps to the proposal

| Proposal | This project |
|---|---|
| Fast filter, under 5 ms | `app/pipeline.py` FastFilter (rules + decision cache) |
| Agent 1: Isolation Forest | `app/agents.py` AnomalyAgent (same model) |
| Agent 2: character-level CNN | `app/agents.py` PayloadAgent (character n-gram model, see below) |
| Agent 3: LSTM | `app/agents.py` BehaviorAgent (Markov sequence model, see below) |
| Agents run in parallel | ThreadPoolExecutor, 3 workers, shared timeout (`agents.timeout_ms`); a slow or broken agent is left out and the decision is marked degraded |
| Confidence-weighted voting | `app/decision.py` aggregate(): mode A (ours), B (equal average) and C (majority vote), chosen in `config.json` |
| Weights update automatically | `app/decision.py` WeightManager: MCC per agent, moving average toward relative performance, bounded 0.1–2.0, max change 0.2 per update, skipped if fewer than 30 attacks in the window. Every update is stored in the `weight_updates` table and reloaded on restart. Every 100 labels in the demo config (SRS default 1,000) |
| Explainable AI | `app/decision.py` explain(): plain text plus a structured part (scores, confidences, weights, contributions, thresholds, missing agents) |
| If every agent fails | Failure policy in `config.json`: `fail_open_flag` (forward and FLAG for review, default) or `fail_closed` (BLOCK) |
| Dashboard and audit log | `static/index.html`, SQLite file `audit.db` |

## Differences from the written proposal (say this before they ask)

- **Spring Boot, Kafka, Go, Redis, PostgreSQL and React are replaced** by one Python process with SQLite and an in-memory cache. Docker Compose is provided (two containers). Reason: it must run on any lab machine without setup. The pipeline stages are the same, and each is its own class, so each can be moved into its own service later.
- **The CNN and LSTM are replaced** by lighter models with the same job (read the payload, learn sequences). They train in seconds and need no GPU or TensorFlow. If your teachers require deep learning, swap those two classes in `app/agents.py`. They only need `analyze()` to return a score and a confidence.
- **The dashboard refreshes by polling every 1.2 seconds**, not by WebSocket.
- **Explanations are template text** filled with what the models actually found. A language model does not write them.
- **Adaptive weights need labels.** In the demo, labels come from the simulator and from analyst clicks. With real traffic you only have analyst clicks.

## Limits to be honest about

- All data is synthetic and made by the same generator that trained the agents. Known-attack scores are optimistic. The "novel" attacks (obfuscated variants held out of training) are the fairer test. To claim real accuracy, evaluate on a public dataset such as CSIC 2010.
- **The old headline result does not hold.** The first version of `evaluate.py` counted a detection at score ≥ 0.5, while the live system flags at ≥ 0.3. With the live thresholds, confidence-weighted (A) and plain averaging (B) both reach PR-AUC 1.000 on this synthetic test, and majority voting (C) is close behind (0.951) with more false alarms (3.2% vs 0.5%). On this data, the advantage over averaging is not shown. Real data and the CNN/LSTM agents are needed before claiming one.
- Most attacks end as **FLAG** (score 0.3 to 0.7), not BLOCK: about 26% of attacks reach BLOCK. Averaging three agents pulls scores toward the middle. Tune `thresholds` in `config.json` on the validation split, never on the test split.
- Behavior history is kept in memory per user and resets when the server restarts.

## Files

```
run.py                start everything
evaluate.py           compares voting methods, writes results/evaluation.md
app/traffic.py        synthetic normal, attack and scanner traffic
app/agents.py         the three agents
app/config.py         loads and checks config.json
app/decision.py       aggregation modes, verdict bands, adaptive weights, explanations
tests/                unit tests (decision engine, config, timeouts, failure policy)
config.json           all tunable settings
app/pipeline.py       session store, fast filter, parallel agents, audit log
app/server.py         gateway (identity, rate limit, forwarding), dashboard API, simulator
app/auth.py           accounts, password hashing, sessions, roles, CSRF, lockout
manage_users.py       add / change / disable dashboard accounts
static/login.html     sign-in page
demo_api/app.py       the demo shop API the gateway protects
Dockerfile, docker-compose.yml   two-container deployment
static/index.html     dashboard
```
