**Scope Deviation Report**

How far the adapted project (SRS v1.1) departs from the original
proposal

**Project:** Adaptive Multi-Agent and Explainable AI System for
Real-Time API Threat Detection

**Version:** 1.0

**Date:** 13 October 2026

**Compares:** Original proposal and system flow → SRS v1.0 → prototype
(8 Oct 2026) → SRS v1.1

**Purpose:** Show the supervisor, openly and in one place, what changed,
what did not, and why

1\. Summary

The original proposal makes **35 concrete commitments** (components,
models, targets, dashboard features). In the adapted scope:

| **Status** | **Count** | **Share** | **Meaning**                                                       |
|------------|-----------|-----------|-------------------------------------------------------------------|
| Kept       | 19        | 54%       | Delivered as proposed (sometimes made more precise or measurable) |
| Changed    | 13        | 37%       | Same purpose, different technology or definition                  |
| Deferred   | 1         | 3%        | Not in the committed scope; may be added if time permits (T2)     |
| Dropped    | 2         | 6%        | Removed from this project; recorded as future work                |

**Overall deviation: 46% of the proposal's commitments are not delivered
exactly as written.** But the deviation is almost entirely in the
plumbing:

- **Architecture and infrastructure:** 3 of 12 kept (25%). Kafka, Go,
  Spring Boot, Redis, PostgreSQL, Prometheus/Grafana and React are
  replaced, made optional or removed.

- **Research core (AI, decision, explainability, performance,
  dashboard):** 16 of 23 kept (70%). The rest are changed only to make
  them correct or measurable (bounded score formula, label-based
  weights, synchronous analysis, adjudication instead of override).

- **Nothing in the research contribution was removed.** Three parallel
  agents, the same three models, confidence-weighted voting, adaptive
  weights, the fast filter, the 0.3/0.7 thresholds, the 5 ms and 200 ms
  targets and plain-English explanations are all still in scope.

<img src="media/b656f7f187359cf7c38a0afc47a2f8204c920e91.png"
style="width:5in;height:2.5in" />

Figure 1. Proposal commitments by area and status. Counts are printed on
each segment; Table 3 lists every item.

Size of the system, before and after

| **Measure**                    | **Proposal / SRS v1.0**                                   | **SRS v1.1**                                 | **Change** |
|--------------------------------|-----------------------------------------------------------|----------------------------------------------|------------|
| Deployable services            | 11                                                        | 1 application + demo API                     | −9         |
| Server-side languages          | 3 (Java, Python, Go) + JS dashboard                       | 1 (Python) + JS dashboard                    | −2         |
| Infrastructure products to run | 6 (Kafka, Redis, PostgreSQL, Prometheus, Grafana, Docker) | 1 (Docker; SQLite is a file)                 | −5         |
| Requirements                   | 338                                                       | 254 (247 committed, 7 conditional)           | −84 (−25%) |
| Open decisions                 | 24                                                        | 5 (3 carried, 2 new supervisor items)        | −19        |
| Datasets                       | None chosen                                               | SR-BH 2020, team generator, CSIC 2010 (test) | Added      |

2\. The four versions compared

| **Aspect**      | **Proposal + flow (Jul)**      | **SRS v1.0 (Aug)**                    | **Prototype (8 Oct)**                         | **SRS v1.1 (Oct)**                            |
|-----------------|--------------------------------|---------------------------------------|-----------------------------------------------|-----------------------------------------------|
| Gateway         | Spring Boot                    | Spring Boot (OD-26 raised)            | Flask                                         | Flask                                         |
| Path to agents  | Kafka, asynchronous            | Synchronous; Kafka on audit path only | Thread pool, synchronous                      | Thread pool, synchronous                      |
| Payload model   | Character CNN                  | CNN proposed, open                    | Char n-gram + logistic regression             | CNN; n-gram as baseline                       |
| Behaviour model | LSTM                           | LSTM proposed, open                   | Markov chain                                  | LSTM; Markov as baseline                      |
| Decision engine | Go                             | Go deferred to T2                     | Python                                        | Python                                        |
| Score formula   | S × C × W                      | Normalised weighted mean              | Normalised weighted mean                      | Normalised weighted mean, modes A/B/C         |
| Weight update   | Every 1 000 requests, accuracy | Labelled outcomes; rule open          | Accuracy⁴ every 100 labels                    | MCC + bounded EMA every N labels              |
| Data            | Not stated                     | Open (OD-05)                          | Synthetic only                                | SR-BH + generator + CSIC test                 |
| Storage / state | PostgreSQL, Redis Cluster      | PostgreSQL, Redis                     | SQLite, in-memory                             | SQLite, in-memory (Postgres/Redis T2)         |
| Dashboard       | React, WebSocket, 7 widgets    | React, push, 7 widgets                | HTML/Chart.js, polling, 6 widgets + simulator | HTML/Chart.js, polling, 7 widgets + simulator |
| Auth            | Not mentioned                  | 3 roles, mandatory                    | None                                          | 2 roles, mandatory                            |
| Monitoring      | Prometheus + Grafana           | Metrics endpoint; stack T2            | Stats endpoint                                | Stats + health endpoints                      |
| Deployment      | Docker Compose                 | Docker Compose, 11 services           | python run.py                                 | Docker Compose, 2 containers                  |

3\. Item-by-item ledger

Every commitment found in the proposal \[S1\] and the system flow
diagram \[S2\], with its status in SRS v1.1.

| **\#** | **Original commitment**                                             | **In SRS v1.1**                                                                                | **Status** | **Why**                                                                                                                       |
|--------|---------------------------------------------------------------------|------------------------------------------------------------------------------------------------|------------|-------------------------------------------------------------------------------------------------------------------------------|
| A1     | Independent microservices, one per component                        | One Python process with separate internal modules; each module keeps a service-ready interface | Changed    | Removes network hops and cross-service plumbing; the pipeline stages are identical                                            |
| A2     | API Gateway in Spring Boot (Java)                                   | Flask gateway in Python                                                                        | Changed    | Nobody needs to learn Spring; shares code with the agents; one language                                                       |
| A3     | Apache Kafka routes requests to agents                              | Agents called directly in parallel; audit records go through an in-process queue               | Dropped    | Kafka cannot return a verdict to the client in time (v1.0 G-1); on one laptop it only adds latency and failure modes          |
| A4     | Decision engine in Go                                               | Decision engine in Python, same formula                                                        | Changed    | Aggregation is a few multiplications; no measured bottleneck to justify a fourth language                                     |
| A5     | Redis Cluster for cache and session state                           | In-memory store behind an interface; Redis optional (T2)                                       | Changed    | Single process needs no shared cache; interface keeps the Redis option open                                                   |
| A6     | PostgreSQL audit database                                           | SQLite through one data-access module; PostgreSQL optional (T2)                                | Changed    | Zero setup on lab machines; same schema                                                                                       |
| A7     | React.js + Recharts dashboard                                       | Plain HTML/JS + Chart.js dashboard now; React port is T2                                       | Deferred   | A working dashboard already exists; React adds no research value before mid-eval                                              |
| A8     | Live updates over WebSocket                                         | Polling every ≤ 2 s                                                                            | Changed    | Meets the same "live" need with no extra server code                                                                          |
| A9     | Prometheus + Grafana monitoring                                     | JSON stats and health endpoints shown in the dashboard                                         | Dropped    | A second UI showing the same numbers; two more containers for no marks                                                        |
| A10    | Docker + Docker Compose                                             | Docker Compose with two containers (System, demo API)                                          | Kept       | —                                                                                                                             |
| A11    | Python + TensorFlow / scikit-learn for agents                       | Same                                                                                           | Kept       | —                                                                                                                             |
| A12    | Gateway does feature extraction, rate limiting, IP check            | Same, plus 429 responses and untrusted identity headers ignored                                | Kept       | —                                                                                                                             |
| B1     | Agent 1: Isolation Forest                                           | Same, with a defined 17-feature vector                                                         | Kept       | —                                                                                                                             |
| B2     | Agent 2: character-level CNN                                        | Same (n-gram model kept as a comparison baseline)                                              | Kept       | —                                                                                                                             |
| B3     | Agent 3: LSTM on session sequences                                  | Same, as supervised classification over the last 20 events (Markov model kept as baseline)     | Kept       | —                                                                                                                             |
| B4     | Three agents run in parallel                                        | Same (thread pool, per-agent timeout)                                                          | Kept       | —                                                                                                                             |
| B5     | Suspicious requests passed to agents asynchronously                 | Agents called synchronously so a verdict exists before the request is served                   | Changed    | Asynchronous analysis cannot block an attack in time (v1.0 critical issue 1)                                                  |
| B6     | Final score = Score × Confidence × Weight                           | T = Σ sᵢcᵢwᵢ / Σ cᵢwᵢ (same terms, normalised to \[0, 1\])                                     | Changed    | The original product is not bounded to \[0, 1\], so the 0.3/0.7 thresholds would not work                                     |
| B7     | Weights update every 1 000 requests by recent accuracy              | Update every N labelled outcomes using MCC and a bounded moving average                        | Changed    | Accuracy needs ground truth, which unlabelled requests do not have; plain accuracy rewards a lazy agent under class imbalance |
| B8     | Thresholds: \< 0.3 ALLOW, 0.3–0.7 FLAG, \> 0.7 BLOCK                | Same, configurable                                                                             | Kept       | —                                                                                                                             |
| B9     | Detects SQLi, XSS, command injection                                | Same, plus path traversal, scanning, credential stuffing, scraping                             | Kept       | Extended so the anomaly and behaviour agents have their own attack classes                                                    |
| B10    | Detect novel (zero-day) variants                                    | Same, made measurable: SSTI/SSRF held out, obfuscated variants, CSIC cross-test                | Kept       | —                                                                                                                             |
| C1     | Plain-English explanation for every decision                        | Same (template text from real model evidence)                                                  | Kept       | —                                                                                                                             |
| C2     | Explanation names the agent, the pattern and the recommended action | Same                                                                                           | Kept       | —                                                                                                                             |
| D1     | Fast filter decides in under 5 ms                                   | Same, measured at the 99th percentile                                                          | Kept       | —                                                                                                                             |
| D2     | ~80% of traffic skips the AI                                        | Reported as an observed metric, not a requirement                                              | Changed    | A filter can hit any percentage by being permissive; making it a target would hurt detection                                  |
| D3     | Under 200 ms end to end                                             | Same, at the 95th percentile on the declared demo laptop                                       | Kept       | —                                                                                                                             |
| D4     | Identical requests cached in Redis                                  | In-memory cache keyed on a payload digest; never bypasses signature rules                      | Changed    | Follows A5; digest key stops cache-poisoning                                                                                  |
| E1     | Live request counter                                                | Same                                                                                           | Kept       | —                                                                                                                             |
| E2     | Attack type breakdown chart                                         | Same                                                                                           | Kept       | —                                                                                                                             |
| E3     | Latency timeline flagging \> 200 ms                                 | Same                                                                                           | Kept       | —                                                                                                                             |
| E4     | Agent performance over time                                         | Same (weights and recent performance)                                                          | Kept       | —                                                                                                                             |
| E5     | Recent decisions feed with XAI text                                 | Same                                                                                           | Kept       | —                                                                                                                             |
| E6     | Health lights for microservices, Kafka, Redis, database             | Health of internal components (gateway, filter, agents, engine, store)                         | Changed    | Follows A1, A3, A5                                                                                                            |
| E7     | Manual override panel (approve or block)                            | Adjudication: malicious / benign / undetermined, with justification; feeds weight learning     | Changed    | A past request cannot be re-blocked; the useful part is the label                                                             |

4\. What was added

These were not in the proposal. They were added because the project
cannot be evaluated or defended without them.

| **Addition**                                        | **Why it was needed**                                                                     |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------|
| Datasets: SR-BH 2020, team generator, CSIC 2010     | The proposal names no data. Without real traffic, results only measure our own generator. |
| Held-out attack family (SSTI, SSRF)                 | Makes the "zero-day" objective a real experiment instead of a claim.                      |
| Light baseline models (n-gram, Markov)              | Already built. Comparing them with the CNN and LSTM turns a deviation into a result.      |
| Aggregation modes B and C                           | Needed to prove confidence-weighting beats majority voting (OBJ-2).                       |
| Offline replay / evaluation mode                    | Every number in the final report comes from it.                                           |
| Defined confidence formulas and calibration checks  | The proposal uses confidence but never defines it; it is the core of the contribution.    |
| Demo protected API and traffic generator            | Something real to protect and to drive the live demo.                                     |
| Analyst login with two roles                        | An unauthenticated dashboard on a security project is an obvious examiner finding.        |
| Fail-open-with-FLAG policy, timeouts, degraded mode | Says what happens when an agent fails.                                                    |
| Untrusted identity headers                          | The prototype let attackers reset their history by changing one header.                   |
| Same thresholds in evaluation and live system       | The prototype reported detection at 0.5 while the live system used 0.3/0.7.               |

5\. Requirement changes from SRS v1.0

| **Category**   | **v1.0** | **Withdrawn or merged** | **New** | **v1.1** |
|----------------|----------|-------------------------|---------|----------|
| Functional     | 107      | 10                      | 7       | 104      |
| AI/ML          | 69       | 8                       | 5       | 66       |
| Explainability | 21       | 5                       | 0       | 16       |
| Non-functional | 44       | 17                      | 1       | 28       |
| Security       | 36       | 17                      | 1       | 20       |
| Data           | 30       | 19                      | 2       | 13       |
| Interface      | 31       | 24                      | 0       | 7        |
| Total          | 338      | 100                     | 16      | 254      |

> The requirement count falls less than the architecture does, on
> purpose. Most v1.0 requirements describe what the detector must do,
> record and prove, and those all still apply. The big saving is in
> effort: 11 services in 3 server languages becomes one Python code base
> the team already has running.

Withdrawn or merged IDs

Grouped by reason. IDs are never reused.

| **Reason**                                                                      | **IDs**                                                                                                                                                                                                 |
|---------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Message broker / event stream removed (ADD-17)                                  | FR-061, NFR-016, UI-015, UI-016, UI-017, UI-018, DATA-018                                                                                                                                               |
| Multi-service deployment removed (ADD-16)                                       | FR-029, FR-032, AI-007, NFR-011, NFR-012, NFR-013, NFR-022, NFR-027, NFR-030, SEC-004, SEC-005, UI-006, UI-007, UI-008, UI-010, UI-011, UI-012, UI-013, UI-014, UI-019, UI-020, UI-021                  |
| Merged into DATA-001 (one decision-record requirement)                          | DATA-002 to DATA-011, DATA-014, DATA-015, DATA-022                                                                                                                                                      |
| Admin features simplified (config editing, audit of config changes, third role) | FR-030, FR-087, SEC-013, SEC-014, SEC-015, SEC-017, SEC-018, SEC-019, SEC-020, SEC-021, SEC-024, SEC-026, SEC-031, SEC-032, SEC-036, UI-025, UI-026, UI-027, UI-028, UI-029, UI-031, DATA-020, DATA-021 |
| Covered by other requirements or not testable on its own                        | remaining IDs, listed below                                                                                                                                                                             |

Remaining withdrawn IDs: FR-025, FR-048, FR-049, FR-094, FR-102, AI-034,
AI-044, AI-057, AI-058, AI-060, AI-067, AI-068, XAI-012, XAI-014,
XAI-015, XAI-018, XAI-019, NFR-007, NFR-008, NFR-018, NFR-019, NFR-023,
NFR-032, NFR-033, NFR-038, NFR-040, NFR-041, SEC-002, SEC-008, DATA-028,
DATA-029, DATA-030, UI-001, UI-002, UI-023.

New in v1.1: FR-108, FR-109, FR-110, FR-111, FR-112, FR-113, FR-114,
AI-070, AI-071, AI-072, AI-073, AI-074, NFR-045, SEC-037, DATA-031,
DATA-032.

6\. What the code must change

The prototype already covers most of the pipeline. These are the changes
needed to meet SRS v1.1, with an owner each.

| **\#** | **Change**                                                                                                     | **Owner**                  | **Requirements**           |
|--------|----------------------------------------------------------------------------------------------------------------|----------------------------|----------------------------|
| 1      | Load SR-BH and CSIC; build splits; extend generator with SSTI, SSRF, credential stuffing, scraping             | NOxiee + Shrey             | AI-059–063, DATA-\*        |
| 2      | Character CNN payload agent (port agent2_payload.py); keep n-gram as baseline                                  | NOxiee                     | AI-019–025, AI-071         |
| 3      | LSTM behaviour agent over 20-event window (port agent3_behavior.py); keep Markov as baseline                   | Sehaj                      | AI-026–031, AI-072         |
| 4      | Confidence formulas: tree spread, temperature scaling, history × certainty                                     | Sehaj + NOxiee             | AI-032–037                 |
| 5      | Replace accuracy⁴ weights with MCC + bounded EMA, min-positives rule, stored history                           | Sehaj                      | AI-046–055                 |
| 6      | Modes B and C in the live pipeline; agent timeouts; fail-open FLAG                                             | NOxiee                     | FR-033–036, FR-046         |
| 7      | Evaluation: same thresholds, PR-AUC, ablations, baseline swap, held-out and CSIC reports, reliability diagrams | Sehaj                      | FR-089–097, FR-110–112     |
| 8      | Gateway: forward to demo API, no explanation to clients, X-Request-ID, 429, ignore X-User-Id/XFF               | Navjot                     | FR-050–055, SEC-037        |
| 9      | Demo shop API as its own small Flask app                                                                       | Navjot                     | FR-103                     |
| 10     | Login, two roles, CSRF, session expiry                                                                         | Navjot                     | SEC-006–016, SEC-034       |
| 11     | Config file for all thresholds, rules and model choice; startup validation                                     | Navjot + NOxiee            | FR-016, FR-085–086         |
| 12     | Background audit writer, adjudication table, write-failure counters                                            | Navjot                     | FR-056, FR-064, FR-079–083 |
| 13     | Dockerfile and docker-compose.yml                                                                              | Navjot                     | NFR-042                    |
| 14     | Unit tests: aggregation, band edges, confidence bounds, weight updates, filter rules                           | Shrey (with module owners) | NFR-029                    |
| 15     | Dataset documentation, README endpoint table, results write-up                                                 | Shrey                      | DATA-025, UI-022           |

7\. Plan to the mid-semester evaluation

Assumes mid-eval in about four weeks (around 10–14 November). Adjust the
dates once it is confirmed.

| **Week**         | **Goal**              | **Tasks (from Section 6)**                                                                                                                  | **Done when**                                                            |
|------------------|-----------------------|---------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| 1 (13–19 Oct)    | Agree scope, set up   | Supervisor sign-off on this report and SRS v1.1; team code walkthrough; Git repo; download SR-BH and CSIC; declare demo laptop; start 8, 11 | Supervisor has approved; everyone can explain the existing pipeline      |
| 2 (20–26 Oct)    | Real data in          | 1, 2 (first CNN), 5, 9, 10                                                                                                                  | CNN trained on real data; demo API and login working                     |
| 3 (27 Oct–2 Nov) | Full pipeline on v1.1 | 3, 4, 6, 7 (first run), 12, 13                                                                                                              | LSTM or Markov running live; first replay report on real data; Docker up |
| 4 (3–9 Nov)      | Results and polish    | 7 (final runs), 14, 15; latency benchmark                                                                                                   | Tables: modes A/B/C, ablations, CNN vs n-gram, held-out, CSIC, latency   |
| Buffer           | Rehearse              | Mid-eval slides, demo script, dry run                                                                                                       | Each member presents their own module                                    |

> Minimum for mid-eval if time runs short: real data loaded, CNN trained
> and compared with the n-gram baseline, the fixed evaluation harness,
> login, Docker. The LSTM can be shown as in progress with the Markov
> baseline serving live traffic; SRS v1.1 allows this (RSK-08).

8\. How to present this to the supervisor

1.  **The research question did not change.** Same three agents, same
    models, same voting idea, same thresholds and latency targets.

2.  **The plumbing changed because it could not work as written.** Kafka
    cannot return a verdict in time, the original score formula is not
    bounded to \[0, 1\], and accuracy cannot be computed without labels.
    These were found in the gap analysis, not invented to save effort.

3.  **Language and infrastructure cuts are about delivery risk.** One
    code base for four people instead of eleven services in three server
    languages. Every cut component sits behind an interface and can come
    back (Redis, PostgreSQL, React are T2).

4.  **We added what makes the results believable:** real public data, a
    held-out attack family, baselines, ablations and honest relative
    acceptance criteria.

5.  **Two things need the supervisor's answer:** approval of these
    changes (OD-28) and whether SR-BH, which contains real scanner IPs
    under a CC0 licence, is acceptable (OD-27).
