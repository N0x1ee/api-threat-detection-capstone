**Software Requirements Specification**

Adaptive Multi-Agent and Explainable AI System for Real-Time API Threat
Detection

**Version:** 1.1 (adapted scope), supersedes v1.0

**Standard basis:** ISO/IEC/IEEE 29148:2018, adapted for an academic
capstone

**Programme:** MCA, final-year capstone project

**Status:** Draft for team and supervisor approval

**Date:** 13 October 2026

**Companion document:** Scope Deviation Report v1.0 (how far this
version departs from the original proposal)

Document control

| **Field**                | **Value**                                                                         |
|--------------------------|-----------------------------------------------------------------------------------|
| Project title            | Adaptive Multi-Agent and Explainable AI System for Real-Time API Threat Detection |
| Institution / Department | TBD (team to complete)                                                            |
| Supervisor               | TBD                                                                               |
| Document owner           | Documentation lead                                                                |
| Approval                 | Project guide / faculty supervisor, pending                                       |

Project team

| **Member** | **Responsibility**                                                    |
|------------|-----------------------------------------------------------------------|
| NOxiee     | AI/ML (payload agent, data pipeline); documentation lead for this SRS |
| Sehaj      | AI/ML (behaviour and anomaly agents, evaluation)                      |
| Navjot     | Gateway, demo API, dashboard, authentication, deployment              |
| Shrey      | Documentation, testing and cross-functional support                   |

Revision history

| **Version** | **Date**    | **Description**                                                                                                                                                                                                                                                                 |
|-------------|-------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 0.1         | Aug 2026    | Stage 1 document analysis and gap analysis                                                                                                                                                                                                                                      |
| 1.0         | Aug 2026    | Full SRS from proposal, system flow and gap analysis (338 requirements, 11 services, pre-implementation)                                                                                                                                                                        |
| 1.0-DR      | Aug 2026    | Decision Resolution report: recommendations for all open decisions                                                                                                                                                                                                              |
| 1.1.1       | 13 Oct 2026 | Data facts after downloading SR-BH: per-class split instead of per-day (AI-062), DS-1 description, behaviour validation dropped, new AI-074 (scan URL path).                                                                                                                    |
| 1.1         | 13 Oct 2026 | Scope adapted to what is plausible for a four-person team. Adopts the Decision Resolution recommendations, records the single-process Python architecture already prototyped, closes 21 of 25 open decisions, and trims the requirement set to what will be built and verified. |

**Contents**

(Right-click the table and choose Update Field if page numbers are
missing.)

1\. Introduction

1.1 Purpose

This document specifies what the System shall do. It is the baseline
against which the implementation, the mid-semester evaluation and the
final evaluation are judged. Version 1.1 replaces v1.0. It keeps the
research intent of the original proposal but resizes the engineering to
what four students can build, evaluate and defend in one session.

Like v1.0, this SRS contains requirements, not results. Every number in
it is a target or a configuration default, never a measured outcome.

1.2 What changed from v1.0, in one table

| **Area**       | **v1.0**                                                                                      | **v1.1**                                                                                                                                                                  |
|----------------|-----------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Architecture   | 11 services, 4 languages (Java, Python, Go, JS), Kafka, Redis, PostgreSQL, Prometheus/Grafana | One Python application with separate internal modules, plus a browser dashboard. Two languages. SQLite, in-memory state store. Docker Compose for one-command deployment. |
| Models         | Isolation Forest, character CNN, LSTM "proposed", final choice open                           | Committed: Isolation Forest, character CNN, LSTM. The light models already built (character n-gram, Markov chain) are kept as comparison baselines.                       |
| Data           | Undecided (OD-05)                                                                             | Hybrid: SR-BH 2020 (real traffic) + team traffic generator + CSIC 2010 as a cross-dataset test. SSTI and SSRF held out as the "zero-day" family.                          |
| Open decisions | 24 open (OD-01 already closed)                                                                | 3 carried over (OD-10, OD-23, OD-25) and 2 new supervisor items. The other 21 are closed by adopted decisions ADD-16 to ADD-33 (Section 3.4).                             |
| Requirements   | 338                                                                                           | 254 (247 committed, 7 conditional). Requirements serving only the dropped infrastructure were removed; research and evaluation requirements were kept. See Appendix A.    |
| Status         | Nothing implemented                                                                           | A working prototype exists (Oct 2026). Section 3.6 maps it to this SRS.                                                                                                   |

> Requirement IDs from v1.0 are kept where the requirement survives, so
> traceability is not broken. New requirements continue the numbering
> (FR-108 onward, AI-070 onward, and so on). Gaps in numbering are
> requirements withdrawn in v1.1; they are listed in the Scope Deviation
> Report.

1.3 Problem statement

APIs are a primary attack surface. The proposal identifies three
weaknesses in current API security tooling:

1.  **Too many false alarms.** Single-model detectors flag legitimate
    traffic.

2.  **No explanation.** Analysts cannot see why a request was blocked.

3.  **Too slow.** Deep analysis of every request adds unacceptable
    latency.

The project tests the hypothesis that combining three specialised
detectors with confidence-aware weighting beats simple majority voting,
while a cheap rule filter keeps the system fast and every decision comes
with a plain-English reason. This is a hypothesis to test, not a claim.

1.4 Objectives

| **ID** | **Objective**                                                                                                               |
|--------|-----------------------------------------------------------------------------------------------------------------------------|
| OBJ-1  | Build a detection system in which three specialised models analyse a request in parallel.                                   |
| OBJ-2  | Implement confidence-weighted aggregation and make it measurable against simple majority voting and equal-weight averaging. |
| OBJ-3  | Meet a real-time latency target by letting a rule-based fast filter clear ordinary traffic without model inference.         |
| OBJ-4  | Produce a human-readable explanation for every decision.                                                                    |
| OBJ-5  | Detect both attack types seen in training and attack families withheld from training, and report the two separately.        |

1.5 Product scope

The System is an inspection layer in front of an HTTP/REST API. For each
request it returns **ALLOW**, **FLAG** or **BLOCK**, attaches an
explanation, stores an audit record and shows the result on an analyst
dashboard. It is a **research prototype** that runs on one laptop. It is
not a production WAF.

1.6 Definitions

| **Term**                    | **Meaning**                                                                                                                   |
|-----------------------------|-------------------------------------------------------------------------------------------------------------------------------|
| Agent score (sᵢ)            | Threat evidence from agent i for one request, in \[0, 1\]. Higher means more suspicious.                                      |
| Agent confidence (cᵢ)       | How reliable agent i says its own score is for this request, in \[0, 1\], independent of the score value.                     |
| Agent weight (wᵢ)           | Agent i's recent measured performance on labelled outcomes, in \[w_min, w_max\].                                              |
| Final threat score (T)      | Aggregate of all participating agents, in \[0, 1\].                                                                           |
| Verdict                     | ALLOW, FLAG or BLOCK, derived from T and two thresholds.                                                                      |
| Bypass path / analysis path | Requests cleared by the fast filter / requests sent to the agents.                                                            |
| Labelled outcome            | A decision with an authoritative ground-truth label, from a corpus run or an analyst adjudication.                            |
| Replay mode                 | Offline run of a labelled dataset through the full pipeline to produce metrics.                                               |
| Baseline model              | A light model kept for comparison: character n-gram + logistic regression (payload) and first-order Markov chain (behaviour). |
| Held-out family             | Attack classes never used in training or tuning (SSTI, SSRF), used only to test OBJ-5.                                        |
| Behavioural identity        | Who a request is attributed to for sequence analysis (session, token, API key or IP).                                         |

1.7 Conventions

- **shall** = binding requirement; **should** = recommendation; **may**
  = optional. Only "shall" statements are requirements.

- **Tier T1** = committed for final delivery. **Tier T2** = built if
  time permits; binding only if built.

- **Verification:** T = test, D = demonstration, I = inspection, A =
  analysis of measured data.

1.8 References

| **Ref** | **Source**                                                                                                                                                                                           |
|---------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| \[S1\]  | Project team (prepared by Navjot Singh), Adaptive Multi-Agent & Explainable AI System for Real-Time API Threat Detection: research proposal. Internal. Primary source of intent.                     |
| \[S2\]  | API Threat Detection: System Flow diagram. Internal.                                                                                                                                                 |
| \[S3\]  | A. Mittal, P. Keshap, A. Hosabettu, "AI-Driven Real-Time API Security: Explainable Threat Detection for Cloud Environments," IEEE ICCST 2025, doi:10.1109/ICCST63435.2025.11293949. Background only. |
| \[S4\]  | C. Islam, Z. Mousavi, M. A. Babar, A. Abuadbba, "Detecting Misuse of Security APIs: A Systematic Review," ACM Computing Surveys, 2025, doi:10.1145/3735968. Background only.                         |
| \[S5\]  | SRS v1.0 and the SRS Decision Resolution report v1.0. Internal.                                                                                                                                      |
| \[S6\]  | Scope Deviation Report v1.0. Internal companion to this SRS.                                                                                                                                         |
| \[D1\]  | Riera et al., SR-BH 2020 multi-label web attack dataset, Harvard Dataverse, doi:10.7910/DVN/OGOIXX (CC0 1.0).                                                                                        |
| \[D2\]  | CSIC 2010 HTTP dataset; line-terminator artifact documented in HTTP2vec, arXiv:2108.01763.                                                                                                           |
| \[D3\]  | SecLists and PayloadsAllTheThings payload collections (MIT).                                                                                                                                         |

2\. Overall Description

2.1 Product perspective

Clients send requests to the System's gateway instead of the protected
API. The gateway inspects each request, decides, and forwards or rejects
it. An analyst watches decisions and reviews flagged requests on the
dashboard. All of it runs as one Python application (plus a small demo
API it protects) on one machine.

| **Element**        | **Role**                                                                                                                              |
|--------------------|---------------------------------------------------------------------------------------------------------------------------------------|
| API clients        | Browsers, apps, scripts and the traffic generator. Talk only to the gateway.                                                          |
| The System         | Gateway, fast filter, three agents, decision engine, explanation layer, audit store, dashboard API. One process.                      |
| Demo protected API | Small shop-style REST API (login, products, search, cart, orders, files) that the System protects. Not reachable directly by clients. |
| Security analyst   | Uses the dashboard: monitors, inspects explanations, adjudicates flagged requests.                                                    |

2.2 Product functions

1.  Receive requests and extract features.

2.  Clear ordinary traffic with a rule-based fast filter.

3.  Send suspicious requests to three agents in parallel.

4.  Combine agent outputs with confidence-weighted aggregation.

5.  Classify as ALLOW, FLAG or BLOCK and enforce the verdict.

6.  Explain every decision in structured and plain-English form.

7.  Store an immutable audit record of every decision.

8.  Show live and historical activity on an authenticated dashboard.

9.  Let analysts adjudicate flagged requests; use adjudications as
    labelled outcomes.

10. Adapt agent weights from labelled outcomes.

11. Run offline replay evaluation with ablations and baseline
    comparisons.

2.3 User classes

| **Class**     | **Description**                                                                           | **Privilege**        |
|---------------|-------------------------------------------------------------------------------------------|----------------------|
| API client    | Automated caller of the protected API. No System interface beyond the gateway.            | None                 |
| Analyst       | Monitors decisions, reads explanations, adjudicates flagged requests, runs the simulator. | Read all; adjudicate |
| Administrator | Configures thresholds and rules, resets data, freezes weights, runs replay.               | Full                 |
| Evaluator     | Supervisor or examiner. Uses an Analyst account for the demo.                             | As Analyst           |

> v1.0 had a separate read-only Observer role. It is merged into Analyst
> in v1.1; evaluators are given an Analyst account.

2.4 Operating environment

| **Aspect**         | **Specification**                                                                                                                                     |
|--------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------|
| Deployment         | Single host. docker compose up (two containers: System, demo API) or python run.py without Docker.                                                    |
| Language / runtime | Python 3.11 or later for all server code. HTML, CSS and JavaScript for the dashboard.                                                                 |
| Libraries          | Flask, scikit-learn, NumPy, TensorFlow/Keras (CPU) or PyTorch (CPU) for the CNN and LSTM; Chart.js for dashboard charts.                              |
| Storage            | SQLite file for audit records and weights. PostgreSQL is a T2 option behind the same data-access layer.                                               |
| Reference hardware | The team's demo laptop, declared before the first benchmark: CPU model \_\_\_\_, cores \_\_\_\_, RAM \_\_\_\_, storage \_\_\_\_, OS \_\_\_\_. (OD-10) |
| GPU                | Not required. Training may use a GPU or Colab; inference shall run on CPU.                                                                            |
| Network            | Local only. No cloud deployment.                                                                                                                      |

2.5 Constraints

| **ID** | **Constraint**                                                                                                               |
|--------|------------------------------------------------------------------------------------------------------------------------------|
| CON-01 | The complete System shall deploy with one documented command on one host.                                                    |
| CON-02 | All inference shall run on CPU within the latency budget of Section 7.                                                       |
| CON-03 | Four-person student team, one academic session. Mid-semester evaluation in about four weeks from this version.               |
| CON-04 | Only free, openly licensed software.                                                                                         |
| CON-05 | No private production traffic. Data is public research corpora or team-generated.                                            |
| CON-06 | Server code in one language (Python). JavaScript only in the dashboard. Any extra language needs a recorded design decision. |
| CON-07 | Payloads must be readable in cleartext at the gateway. Encrypted bodies are out of scope.                                    |
| CON-08 | Every tunable number (thresholds, timeouts, window sizes, weight bounds) shall live in the configuration file, not in code.  |

2.6 Assumptions

| **ID** | **Assumption**                                                                                      | **If false**                                                                                |
|--------|-----------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| ASM-01 | TLS ends at or before the gateway, so payloads are readable.                                        | Payload agent cannot work.                                                                  |
| ASM-02 | Most benign traffic is clearable by the fast filter (the proposal suggests about 80%).              | More load reaches the agents; latency target harder.                                        |
| ASM-03 | Requests can be attributed to a stable behavioural identity.                                        | Behaviour agent loses most of its value.                                                    |
| ASM-04 | SR-BH and CSIC remain downloadable and usable under their licences.                                 | Fall back to generated data only; state it as a limitation.                                 |
| ASM-05 | Labelled outcomes come from corpus runs and analyst adjudication, not from live unlabelled traffic. | Weight adaptation cannot be demonstrated.                                                   |
| ASM-06 | The demo laptop can run a CNN and an LSTM on CPU within budget.                                     | Latency target renegotiated with the supervisor, or baseline models used for the live demo. |

2.7 Out of scope (non-goals)

| **ID** | **Non-goal**                                                                                                                                 |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------|
| NG-01  | Replacing a production web application firewall.                                                                                             |
| NG-02  | Decrypting third-party TLS traffic.                                                                                                          |
| NG-03  | Authorisation-logic attacks (BOLA, BFLA). No public dataset labels them at traffic level.                                                    |
| NG-04  | Multi-tenancy, clustering, high availability, autoscaling, cloud deployment.                                                                 |
| NG-05  | Robustness against an attacker who knows the models.                                                                                         |
| NG-06  | Automatic remediation beyond the three verdicts.                                                                                             |
| NG-07  | Non-HTTP protocols (gRPC, WebSocket, GraphQL subscriptions).                                                                                 |
| NG-08  | Message broker (Kafka), compiled decision engine (Go), JVM gateway (Spring Boot), Prometheus/Grafana. Removed in v1.1; see ADD-16 to ADD-22. |

2.8 Scope tiers

<table>
<colgroup>
<col style="width: 50%" />
<col style="width: 50%" />
</colgroup>
<thead>
<tr class="header">
<th><strong>Tier 1: committed</strong></th>
<th><strong>Tier 2: if time permits</strong></th>
</tr>
</thead>
<tbody>
<tr class="odd">
<td><p>Gateway with feature extraction, rate limiting and forwarding to
the demo API</p>
<p>Fast filter with externalised rules and decision cache</p>
<p>Anomaly agent (Isolation Forest)</p>
<p>Payload agent (character CNN) + n-gram baseline</p>
<p>Behaviour agent (LSTM) + Markov baseline</p>
<p>Decision engine with modes A, B, C</p>
<p>Adaptive weights from labelled outcomes</p>
<p>Template-based explanations</p>
<p>SQLite audit store with background writer</p>
<p>Dashboard: counters, feed, attack breakdown, latency, agent weights,
health, review queue</p>
<p>Analyst login with two roles</p>
<p>Replay evaluation with ablations and held-out reporting</p>
<p>Demo API and traffic generator</p>
<p>Docker Compose deployment</p></td>
<td><p>React port of the dashboard and WebSocket push</p>
<p>PostgreSQL instead of SQLite</p>
<p>Redis instead of the in-memory store</p>
<p>Historical search and filtering in the dashboard</p>
<p>SHAP attribution for the anomaly agent, measured against the latency
budget</p>
<p>Prometheus-format metrics endpoint</p>
<p>OWASP VAmPI + mitmproxy capture as a second generated corpus</p>
<p>FLAG configurable to hold instead of forward</p>
<p>Weight freeze/restore from the UI</p>
<p>TLS on the gateway</p></td>
</tr>
</tbody>
</table>

3\. System Architecture

3.1 Style

A **modular monolith**: one Python process in which each component is
its own module with a narrow interface. Components call each other
in-process. Each module can later be moved into its own service without
changing its interface, but v1.1 does not require that. This removes
network hops, serialisation and cross-language integration, which were
the biggest delivery risks in v1.0 (RSK-03, RSK-07).

Two paths stay separate, as in v1.0 (ADD-01):

- **Enforcement path** (synchronous): produce and apply a verdict before
  the request is served.

- **Audit path** (asynchronous): a background writer thread takes
  decision records from an in-process queue and writes them to the
  database, so persistence never delays the client.

3.2 Components

| **\#** | **Component**      | **Module (current code)**       | **Responsibility**                                                                                            |
|--------|--------------------|---------------------------------|---------------------------------------------------------------------------------------------------------------|
| C-01   | API Gateway        | app/server.py                   | Receives requests, extracts features, resolves identity, rate-limits, runs the pipeline, forwards or rejects. |
| C-02   | Fast Filter        | app/pipeline.py FastFilter      | Rule-based clear/refer decision; decision cache; signature rules.                                             |
| C-03   | Anomaly Agent      | app/agents.py                   | Isolation Forest over a 17-feature structural vector.                                                         |
| C-04   | Payload Agent      | app/agents.py                   | Character CNN over the payload (n-gram baseline selectable).                                                  |
| C-05   | Behaviour Agent    | app/agents.py                   | LSTM over the identity's recent request sequence (Markov baseline selectable).                                |
| C-06   | Decision Engine    | app/decision.py                 | Aggregation modes A/B/C, verdict bands, weight manager, failure policy.                                       |
| C-07   | XAI Layer          | app/decision.py explain()       | Structured explanation and plain-English text from recorded values.                                           |
| C-08   | State Store        | app/pipeline.py SessionStore    | In-memory sequences, rate counters, decision cache. Interface allows a Redis swap (T2).                       |
| C-09   | Audit Store        | SQLite via a data-access module | Decision records, adjudications, weight updates, users, auth events.                                          |
| C-10   | Dashboard          | static/index.html + /api/\*     | Live view, decision detail, review queue, simulator, try-a-request box.                                       |
| E-01   | Demo protected API | new: demo_api/                  | Shop-style REST API the System protects.                                                                      |
| E-02   | Traffic generator  | app/traffic.py                  | Labelled benign, attack, scanner and held-out traffic in sessions.                                            |
| E-03   | Replay evaluator   | evaluate.py                     | Offline metrics, ablations, baseline comparison, report.                                                      |

3.3 Request lifecycle

1.  Client sends a request to the gateway.

2.  Gateway assigns a request ID, extracts features, resolves the
    behavioural identity, updates rate counters, applies the rate limit.

3.  Fast filter checks signatures, endpoint inventory, rate and
    structure. Clean requests are cleared: verdict ALLOW, explanation
    names the rules, no AI.

4.  Referred requests go to the three agents concurrently (thread pool),
    each with a timeout.

5.  Decision engine combines the valid results: T = Σ(sᵢ·cᵢ·wᵢ) /
    Σ(cᵢ·wᵢ), then bands T into a verdict.

6.  XAI layer builds the structured explanation and the plain-English
    text.

7.  Gateway enforces: ALLOW and FLAG forward to the demo API; BLOCK
    returns 403 and is not forwarded.

8.  The decision record is queued for the background writer; the
    dashboard reads it on its next poll.

3.4 Adopted design decisions

Decisions ADD-01 to ADD-15 from v1.0 stay in force except where noted.
ADD-16 onward are new in v1.1 and close the open decisions of v1.0.

| **ID**           | **Decision**                                                                                                                                                                                                                              | **Closes**                                      |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------|
| ADD-01 (amended) | Synchronous enforcement path. The audit path uses an in-process queue and background writer instead of a message broker.                                                                                                                  | G-1                                             |
| ADD-02 – ADD-07  | Unchanged: confidence defined per agent; normalised weighted mean; weights adapt on labelled outcomes; latency stated with percentile, workload and hardware; half-open verdict bands; bypass ratio is an observation, not a requirement. | —                                               |
| ADD-08, ADD-09   | Unchanged: fast filter in-process; explicit threat scope table.                                                                                                                                                                           | —                                               |
| ADD-10 (amended) | Authentication mandatory for the dashboard; two roles instead of three.                                                                                                                                                                   | —                                               |
| ADD-11, ADD-12   | Unchanged: cache key includes payload digest and never bypasses signatures; per-agent timeout with degraded mode.                                                                                                                         | —                                               |
| ADD-13 (amended) | Demo API and generator in scope, built by the team (not VAmPI) for T1.                                                                                                                                                                    | —                                               |
| ADD-14, ADD-15   | Unchanged: replay mode is T1; "Behaviour" in prose, behavior allowed in code.                                                                                                                                                             | —                                               |
| ADD-16           | Single Python code base, modular monolith. Agents are in-process modules with a uniform Python interface. Gateway is Flask.                                                                                                               | OD-26, OD-20, OD-07 (endpoints in Section 10.1) |
| ADD-17           | No Kafka. Audit events go through an in-process queue to a background writer.                                                                                                                                                             | OD-21 (n/a)                                     |
| ADD-18           | No Go. Decision engine stays in Python; a port is not planned.                                                                                                                                                                            | T2-07 (dropped)                                 |
| ADD-19           | SQLite for T1 through one data-access module; PostgreSQL optional (T2). JSON columns for agent evidence and explanations.                                                                                                                 | OD-06                                           |
| ADD-20           | In-memory state store behind an interface; Redis optional (T2).                                                                                                                                                                           | —                                               |
| ADD-21           | Dashboard in plain HTML/JS with Chart.js, refreshed by polling every ≤ 2 s. React and WebSocket are T2.                                                                                                                                   | —                                               |
| ADD-22           | No Prometheus/Grafana. JSON stats and health endpoints; Prometheus format is T2.                                                                                                                                                          | —                                               |
| ADD-23           | Hybrid dataset: SR-BH 2020 + team generator + CSIC 2010 (test only). SSTI and SSRF held out (Section 9).                                                                                                                                  | OD-05, OD-15                                    |
| ADD-24           | Isolation Forest, character CNN and LSTM are the primary models. Character n-gram and Markov models are kept as selectable baselines. LSTM formulation: supervised sequence classification over a sliding window.                         | OD-13, OD-14, OD-17                             |
| ADD-25           | Confidence: anomaly = agreement among trees; payload = temperature-scaled max probability; behaviour = history sufficiency × model certainty (Section 5.6).                                                                               | OD-02                                           |
| ADD-26           | Weights: rescaled MCC per agent, exponential moving average toward relative performance, α = 0.3, bounded and rate-limited (Section 5.8).                                                                                                 | OD-03, OD-04                                    |
| ADD-27           | If no agent returns a result: fail open with FLAG (forward, mark, queue for review). Configurable to fail closed.                                                                                                                         | OD-08                                           |
| ADD-28           | Server-side session cookie (HttpOnly, SameSite=Strict), salted slow password hashes, roles Analyst and Administrator. No inter-service auth needed (single process).                                                                      | OD-09, OD-19                                    |
| ADD-29           | Decoding chain before rules and features: percent-decode up to depth 2, HTML entities, Unicode NFKC; base64 flagged, not decoded. CNN receives once-decoded text. Anomaly attribution by per-feature z-scores; SHAP is T2.                | OD-16, OD-18, OD-12                             |
| ADD-30           | Detection acceptance is relative (Section 12.2), not absolute numbers.                                                                                                                                                                    | OD-22                                           |
| ADD-31           | No automatic deletion of records during the project. Local deployment only.                                                                                                                                                               | OD-11, OD-24                                    |
| ADD-32           | Client-supplied identity headers (X-User-Id, X-Forwarded-For) are ignored unless trusted-proxy mode is enabled in configuration.                                                                                                          | new                                             |
| ADD-33           | Evaluation uses the same verdict thresholds as the live system.                                                                                                                                                                           | new                                             |

3.5 Agent interface

Every agent implements the same Python interface, so the decision engine
needs no agent-specific code:

analyze(request: Request, context: Context) -\> AgentResult where
AgentResult = { name, score ∈ \[0,1\], confidence ∈ \[0,1\], evidence
(dict), model_version, status }.

3.6 Mapping to the October 2026 prototype

A working prototype (api-threat-detection/) already implements most of
the pipeline. The table lists what it already satisfies and what must
change to meet this SRS. Owners and dates are in the Scope Deviation
Report.

| **Area**        | **Already in prototype**                                       | **Must change for v1.1**                                                                                                                                |
|-----------------|----------------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| Gateway         | Flask gateway at /gateway/\*, verdict enforcement              | Forward to a real demo API; stop returning explanations to clients (FR-052); add X-Request-ID; ignore client identity headers (ADD-32); 429 rate limit. |
| Fast filter     | Rules, decision cache, reasons                                 | Move rules to config file; enforce structural bounds; signature matches never cached.                                                                   |
| Agents          | Isolation Forest; n-gram payload model; Markov behaviour model | Add CNN and LSTM as primary; keep current models as baselines; implement ADD-25 confidences; 17-feature vector.                                         |
| Decision engine | Mode A, verdict bands, weight manager (accuracy⁴)              | Modes B and C in the live pipeline; MCC + EMA weights with bounds (ADD-26); timeouts and fail-open FLAG.                                                |
| Explanations    | Template text from real evidence                               | Add thresholds, contribution terms and degraded-mode text to the structured part.                                                                       |
| Storage         | SQLite, synchronous writes                                     | Background writer; adjudication and weight-update tables; users and auth events.                                                                        |
| Dashboard       | Counters, charts, feed, detail, review queue, simulator        | Login; adjudication with justification instead of allow/block override; degraded indicator.                                                             |
| Evaluation      | Voting comparison on synthetic data                            | Real datasets, PR-AUC, ablations, same thresholds as live, held-out and cross-corpus reports, reliability diagrams.                                     |
| Deployment      | python run.py                                                  | Config file, Dockerfile, docker-compose.yml, unit tests.                                                                                                |

4\. Functional Requirements

4.1 Request ingestion

| **ID** | **Requirement**                                                                                                                                                                                                                                                    | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-001 | The System shall accept HTTP/1.1 requests addressed to the protected API through the gateway.                                                                                                                                                                      | T1       | T       |
| FR-002 | The gateway shall accept the methods GET, POST, PUT, PATCH and DELETE.                                                                                                                                                                                             | T1       | T       |
| FR-003 | The System shall assign each request a unique request ID and carry it through every stage and stored record.                                                                                                                                                       | T1       | T       |
| FR-004 | The System shall record the time of receipt with millisecond resolution.                                                                                                                                                                                           | T1       | T       |
| FR-005 | The System shall extract method, path, query string, headers, source IP and content type.                                                                                                                                                                          | T1       | T       |
| FR-006 | The System shall extract the request body, subject to FR-008.                                                                                                                                                                                                      | T1       | T       |
| FR-007 | The System shall compute the 17 structural features listed in Table 5.2.                                                                                                                                                                                           | T1       | T       |
| FR-008 | The System shall inspect at most the first N bytes of a body (default 65 536) and record when truncation occurred.                                                                                                                                                 | T1       | T       |
| FR-009 | The System shall resolve a behavioural identity in this order: session cookie digest, bearer token digest, API key digest, source IP; and record which was used. Client-supplied identity headers shall not be used unless trusted-proxy mode is enabled (ADD-32). | T1       | T       |
| FR-010 | The System shall count requests per identity over a sliding window (default 10 s).                                                                                                                                                                                 | T1       | T       |
| FR-011 | A request that cannot be parsed shall receive BLOCK with the parse failure recorded as the reason.                                                                                                                                                                 | T1       | T       |
| FR-012 | The System shall not change a forwarded request other than by adding documented System headers.                                                                                                                                                                    | T1       | T       |

4.2 Fast filter

| **ID** | **Requirement**                                                                                                    | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-013 | The fast filter shall run on every request before any model inference.                                             | T1       | T       |
| FR-014 | The fast filter shall run in-process in the gateway.                                                               | T1       | I       |
| FR-015 | The fast filter shall classify each request as cleared (ALLOW, no inference) or referred (analysis path).          | T1       | T       |
| FR-016 | Fast filter rules shall be stored in a versioned configuration file and loaded at startup.                         | T1       | I       |
| FR-017 | A request matching a known-attack signature shall always be referred, regardless of cache state.                   | T1       | T       |
| FR-018 | A request from an identity above the rate threshold shall be referred.                                             | T1       | T       |
| FR-019 | A request to an endpoint not in the configured endpoint inventory shall be referred.                               | T1       | T       |
| FR-020 | A request exceeding configured bounds on body size, header count or header length shall be referred.               | T1       | T       |
| FR-021 | The System shall record which rules matched (for referred requests) or which checks passed (for cleared requests). | T1       | T       |
| FR-022 | The decision cache key shall combine method, normalised path and a digest of the inspected payload.                | T1       | I       |
| FR-023 | Cache entries shall expire after a configurable TTL (default 60 s); cache size shall be bounded.                   | T1       | T       |
| FR-024 | A cached ALLOW shall never be served for a request that matches a signature rule.                                  | T1       | T       |
| FR-026 | The share of requests cleared by the fast filter shall be exposed as a metric.                                     | T1       | D       |

4.3 Rate limiting

| **ID** | **Requirement**                                                                             | **Tier** | **Ver** |
|--------|---------------------------------------------------------------------------------------------|----------|---------|
| FR-027 | The gateway shall enforce a configurable request-rate limit per behavioural identity.       | T1       | T       |
| FR-028 | A request over the rate limit shall receive HTTP 429 and a decision record shall be stored. | T1       | T       |

4.4 Agent orchestration

| **ID** | **Requirement**                                                                                                                                              | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-031 | The System shall run the three agents concurrently for every referred request.                                                                               | T1       | T       |
| FR-033 | Each agent call shall have a configurable timeout (default 150 ms).                                                                                          | T1       | T       |
| FR-034 | An agent that times out or errors shall be excluded from aggregation for that request, and the exclusion and cause recorded.                                 | T1       | T       |
| FR-035 | Aggregation shall proceed when at least one agent returns a valid result.                                                                                    | T1       | T       |
| FR-036 | When no agent returns a valid result, the System shall apply the configured failure policy (default: fail open with FLAG, ADD-27) and record that it did so. | T1       | T       |
| FR-037 | All agents shall implement the interface of Section 3.5, so an agent can be added or swapped without changing the decision engine.                           | T1       | I       |
| FR-038 | The System shall record each agent's response time.                                                                                                          | T1       | T       |
| FR-039 | The System shall record every agent output (score, confidence, evidence, model version) for each referred request.                                           | T1       | T       |

4.5 Decision engine

| **ID** | **Requirement**                                                                                                                        | **Tier** | **Ver** |
|--------|----------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-040 | The System shall compute a final threat score T in \[0, 1\] for every referred request using AI-038.                                   | T1       | T       |
| FR-041 | Verdicts shall use two configurable thresholds θ₁ \< θ₂ (defaults 0.3 and 0.7).                                                        | T1       | T       |
| FR-042 | Bands shall be: ALLOW for T \< θ₁, FLAG for θ₁ ≤ T ≤ θ₂, BLOCK for T \> θ₂.                                                            | T1       | T       |
| FR-043 | The System shall refuse to start if θ₁ ≥ θ₂ or either is outside (0, 1).                                                               | T1       | T       |
| FR-044 | Identical agent outputs, weights and thresholds shall always give the same T and verdict.                                              | T1       | T       |
| FR-045 | Each decision shall record T, verdict, thresholds and the weight vector in force.                                                      | T1       | T       |
| FR-046 | The aggregation mode shall be selectable in configuration: A (confidence-weighted, default), B (equal-weight mean), C (majority vote). | T1       | T       |
| FR-047 | Each decision shall record the aggregation mode used.                                                                                  | T1       | T       |

4.6 Verdict enforcement

| **ID** | **Requirement**                                                                                    | **Tier** | **Ver** |
|--------|----------------------------------------------------------------------------------------------------|----------|---------|
| FR-050 | On ALLOW the gateway shall forward the request to the demo API and return its response.            | T1       | T       |
| FR-051 | On BLOCK the gateway shall not forward the request and shall return HTTP 403.                      | T1       | T       |
| FR-052 | Responses to clients shall not reveal scores, thresholds, rules, model outputs or explanations.    | T1       | T       |
| FR-053 | On FLAG the gateway shall forward the request and add it to the analyst review queue.              | T1       | T       |
| FR-054 | FLAG behaviour shall be configurable between forward (default) and hold.                           | T2       | T       |
| FR-055 | Every response shall carry the request ID in the X-Request-ID header.                              | T1       | T       |
| FR-056 | The gateway shall respond as soon as the verdict is enforced, without waiting for the audit write. | T1       | A       |

4.7 Explanations

| **ID** | **Requirement**                                                             | **Tier** | **Ver** |
|--------|-----------------------------------------------------------------------------|----------|---------|
| FR-057 | Every decision on both paths shall have an explanation.                     | T1       | T       |
| FR-058 | Explanations shall be built only from the recorded values of that decision. | T1       | I       |
| FR-059 | Explanations shall be stored in the decision record.                        | T1       | T       |

4.8 Audit persistence

| **ID** | **Requirement**                                                                                       | **Tier** | **Ver** |
|--------|-------------------------------------------------------------------------------------------------------|----------|---------|
| FR-060 | A decision record shall be stored for every decision on both paths.                                   | T1       | T       |
| FR-062 | Records shall survive a restart of the System.                                                        | T1       | T       |
| FR-063 | Each record shall carry the model versions and rule-set version used.                                 | T1       | I       |
| FR-064 | A failed write shall be logged and counted, never silently dropped.                                   | T1       | T       |
| FR-065 | Records shall be queryable by time range, verdict, attack class, identity, source IP and score range. | T1       | T       |
| FR-066 | The System shall not delete decision records automatically during the project (ADD-31).               | T1       | I       |

4.9 Dashboard

| **ID** | **Requirement**                                                                                                                 | **Tier** | **Ver** |
|--------|---------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-067 | The System shall provide a web dashboard available only to authenticated users.                                                 | T1       | D       |
| FR-068 | The dashboard shall show total requests and the share of each verdict, updating live.                                           | T1       | D       |
| FR-069 | The dashboard shall show detections broken down by attack class.                                                                | T1       | D       |
| FR-070 | The dashboard shall show a latency time series and mark points above 200 ms.                                                    | T1       | D       |
| FR-071 | The dashboard shall show a live feed of recent decisions with time, verdict, score, attack class and plain-English explanation. | T1       | D       |
| FR-072 | The dashboard shall update without page reload (polling every ≤ 2 s is acceptable, ADD-21).                                     | T1       | D       |
| FR-073 | An analyst shall be able to open any decision and see per-agent score, confidence, weight and contribution.                     | T1       | D       |
| FR-074 | The dashboard shall show the status of each internal component (gateway, filter, agents, decision engine, store).               | T1       | D       |
| FR-075 | The dashboard shall show each agent's current weight and recent performance over time.                                          | T1       | D       |
| FR-076 | The dashboard shall allow searching and filtering historical decisions using the FR-065 dimensions.                             | T2       | D       |
| FR-077 | The dashboard shall mark decisions made in degraded mode and name the missing agents.                                           | T1       | D       |
| FR-108 | The dashboard shall provide a "try a request" form that sends a crafted request through the pipeline and shows its decision.    | T1       | D       |
| FR-109 | The dashboard shall let an analyst start and stop the traffic simulator in normal, attack, scanner, mixed and held-out modes.   | T1       | D       |

4.10 Analyst review

| **ID** | **Requirement**                                                                                                   | **Tier** | **Ver** |
|--------|-------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-078 | The System shall present a queue of FLAG decisions awaiting review.                                               | T1       | D       |
| FR-079 | An analyst shall be able to adjudicate a decision as confirmed malicious, confirmed benign or undetermined.       | T1       | T       |
| FR-080 | An analyst shall be able to record a corrected verdict. This is recorded only; past requests are not re-enforced. | T1       | T       |
| FR-081 | Each adjudication shall store the analyst, time, outcome and a justification (mandatory for corrected verdicts).  | T1       | T       |
| FR-082 | Adjudications shall be stored as linked records and shall never modify the original decision record.              | T1       | I       |
| FR-083 | A confirmed adjudication shall become a labelled outcome with provenance "analyst".                               | T1       | T       |
| FR-084 | The System shall record the time between a decision entering the queue and its adjudication.                      | T2       | T       |

4.11 Configuration

| **ID** | **Requirement**                                                                                                                                                                                                | **Tier** | **Ver** |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-085 | All tunable parameters shall be read from one configuration file (thresholds, timeouts, weights settings, windows, cache TTL, rate limits, aggregation mode, model selection, failure policy, rules location). | T1       | I       |
| FR-086 | The System shall validate the configuration at startup and refuse to start on an invalid value, naming the parameter.                                                                                          | T1       | T       |
| FR-088 | An administrator shall be able to view the effective configuration in the dashboard.                                                                                                                           | T2       | D       |

4.12 Replay evaluation

| **ID** | **Requirement**                                                                                                                               | **Tier** | **Ver** |
|--------|-----------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-089 | The System shall provide an offline replay mode that runs a labelled dataset through the full pipeline without forwarding.                    | T1       | T       |
| FR-090 | Replay shall use the same feature extraction, agents, aggregation and thresholds as the live gateway.                                         | T1       | I       |
| FR-091 | Replay shall report verdict counts, confusion matrix, precision, recall, F1, PR-AUC, false-positive rate and latency percentiles.             | T1       | T       |
| FR-092 | Replay shall allow any agent to be disabled, so each agent's contribution can be measured.                                                    | T1       | T       |
| FR-093 | Replay shall allow the aggregation mode to be selected.                                                                                       | T1       | T       |
| FR-095 | The replay report shall record the configuration, model versions and dataset versions used.                                                   | T1       | I       |
| FR-096 | Two replay runs with the same data, configuration and models shall give identical metrics.                                                    | T1       | T       |
| FR-097 | Replay shall report the held-out family and the cross-corpus (CSIC) set separately from the main test set.                                    | T1       | T       |
| FR-110 | Replay shall allow each primary model to be replaced by its baseline (CNN ↔ n-gram, LSTM ↔ Markov) so they can be compared on identical data. | T1       | T       |
| FR-111 | Replay shall report detection at two operating points: BLOCK only, and FLAG or BLOCK, both using the live thresholds (ADD-33).                | T1       | T       |
| FR-112 | Replay shall produce a reliability diagram of confidence against observed accuracy for each agent.                                            | T1       | T       |

4.13 Health and observability

| **ID** | **Requirement**                                                                                                                                                  | **Tier** | **Ver** |
|--------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-098 | The System shall expose a health endpoint reporting the status of each component.                                                                                | T1       | T       |
| FR-099 | The System shall record per-stage timing: feature extraction, fast filter, agents, aggregation, explanation.                                                     | T1       | T       |
| FR-100 | The System shall expose a stats endpoint with throughput, verdict counts, bypass share, latency percentiles, agent errors and timeouts, and degraded-mode count. | T1       | D       |
| FR-101 | The System shall write a structured log entry for each decision, agent failure and configuration load.                                                           | T1       | I       |

4.14 Demo environment

| **ID** | **Requirement**                                                                                                                                        | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| FR-103 | The project shall provide a demo API with endpoints for login, products, product detail, search, cart, checkout, orders, settings, feedback and files. | T1       | D       |
| FR-104 | The traffic generator shall produce benign traffic following realistic user flows.                                                                     | T1       | D       |
| FR-105 | The generator shall produce attack traffic for every class in Table 5.1.                                                                               | T1       | D       |
| FR-106 | The generator shall label every request with its true class.                                                                                           | T1       | T       |
| FR-107 | The generator shall organise traffic into sessions per identity.                                                                                       | T1       | T       |
| FR-113 | The generator shall include harmless text that looks risky (apostrophes, SQL keywords in normal words) in benign traffic.                              | T1       | I       |
| FR-114 | The generator shall produce the held-out family (SSTI, SSRF) and obfuscated variants that are never used for training.                                 | T1       | T       |

5\. AI and Machine Learning Requirements

5.1 All agents

| **ID** | **Requirement**                                                                                         | **Tier** | **Ver** |
|--------|---------------------------------------------------------------------------------------------------------|----------|---------|
| AI-001 | The System shall implement an Anomaly Agent, a Payload Agent and a Behaviour Agent.                     | T1       | I       |
| AI-002 | Each agent shall be a separate module that can be replaced or retrained without changing other modules. | T1       | I       |
| AI-003 | Each agent shall implement the interface of Section 3.5.                                                | T1       | T       |
| AI-004 | Each agent shall return a score in \[0, 1\].                                                            | T1       | T       |
| AI-005 | Each agent shall return a confidence in \[0, 1\] defined in Section 5.6.                                | T1       | T       |
| AI-006 | Each agent shall return the evidence that mainly drove its score, in a form the XAI layer can use.      | T1       | T       |
| AI-008 | Each agent shall return its model version with every result.                                            | T1       | T       |
| AI-009 | An agent that cannot evaluate a request shall return an error status, not an invalid score.             | T1       | T       |
| AI-010 | Inference shall be deterministic for a given input and model version; training seeds shall be recorded. | T1       | T       |
| AI-011 | Each agent shall run inference on CPU within its latency budget (Table 7.2).                            | T1       | T       |

5.2 Threat scope

| **ID** | **Requirement**                                                                                         | **Tier** | **Ver** |
|--------|---------------------------------------------------------------------------------------------------------|----------|---------|
| AI-012 | The System shall detect the classes in Table 5.1 and label each detection with a class from that table. | T1       | T       |
| AI-013 | A detection without a determined class shall be labelled "unclassified anomaly".                        | T1       | T       |
| AI-014 | Detection completeness shall be judged only against Table 5.1.                                          | T1       | A       |

**Table 5.1 – Threat scope and agent coverage**

| **Attack class**                       | **Primary agent** | **Support**        | **Data source**                               |
|----------------------------------------|-------------------|--------------------|-----------------------------------------------|
| SQL injection                          | Payload           | Anomaly            | SR-BH (CAPEC-66), generator                   |
| Cross-site scripting                   | Payload           | Anomaly            | Generator (seeded from payload lists)         |
| Command injection                      | Payload           | Anomaly            | SR-BH (CAPEC-88), generator                   |
| Path traversal                         | Payload           | Anomaly            | SR-BH (CAPEC-126), generator                  |
| Scanning / endpoint enumeration        | Behaviour         | Anomaly            | Generator; SR-BH CAPEC-310 as single requests |
| Credential stuffing / brute force      | Behaviour         | Anomaly            | Generator; SR-BH CAPEC-16 as single requests  |
| Scraping / rate abuse                  | Behaviour         | Anomaly            | Generator                                     |
| Malformed or obfuscated requests       | Anomaly           | Payload            | SR-BH, generator                              |
| Held-out: SSTI, SSRF (evaluation only) | Anomaly           | Payload, Behaviour | Generator, never in training                  |

5.3 Anomaly Agent

| **ID** | **Requirement**                                                                                                        | **Tier** | **Ver** |
|--------|------------------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-015 | The Anomaly Agent shall use an Isolation Forest trained only on benign traffic (SR-BH normal + generator benign).      | T1       | I       |
| AI-016 | Raw anomaly output shall be mapped to \[0, 1\] by a documented monotonic function calibrated on validation data.       | T1       | T       |
| AI-017 | The agent shall return the top-k features (default 5) ranked by deviation from the benign mean in standard deviations. | T1       | T       |
| AI-018 | The agent shall not need labelled attack data for training.                                                            | T1       | I       |
| AI-070 | The agent shall use the feature vector of Table 5.2.                                                                   | T1       | I       |

**Table 5.2 – Structural feature vector (17 features)**

| **Group**      | **Features**                                                                                                               |
|----------------|----------------------------------------------------------------------------------------------------------------------------|
| Size (6)       | total request length; payload length; query-string length; header count; mean header value length; max header value length |
| Characters (6) | payload entropy; query entropy; alphabetic ratio; digit ratio; special-character ratio; non-printable count                |
| Structure (5)  | path depth; query parameter count; HTTP method (encoded); content-type category; declared vs actual length mismatch flag   |

5.4 Payload Agent

| **ID** | **Requirement**                                                                                                                                                                              | **Tier** | **Ver** |
|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-019 | The Payload Agent shall use a character-level CNN classifying the payload into SQLi, XSS, command injection, path traversal or benign. Input: once-decoded text, capped at 1 024 characters. | T1       | I       |
| AI-020 | The agent shall return the predicted class, or state that no attack class was determined.                                                                                                    | T1       | T       |
| AI-021 | The agent shall return the payload tokens that most influenced the prediction, for highlighting.                                                                                             | T1       | T       |
| AI-022 | When input was truncated, the agent shall say so in its result.                                                                                                                              | T1       | T       |
| AI-023 | For a request with no payload or query, the agent shall return score 0, minimum confidence and a "not applicable" flag.                                                                      | T1       | T       |
| AI-024 | The decoding chain of ADD-29 shall be applied before rules and feature extraction, and the decodings applied shall be recorded.                                                              | T1       | T       |
| AI-025 | Class probabilities shall be calibrated by temperature scaling on the validation partition.                                                                                                  | T1       | T       |
| AI-074 | The agent shall analyse the URL path as well as the query string and body; in SR-BH many payloads are injected into path segments.                                                           | T1       | T       |
| AI-071 | A character n-gram TF-IDF + logistic regression model shall be kept as a baseline with the same interface, selectable in configuration.                                                      | T1       | T       |

5.5 Behaviour Agent

| **ID** | **Requirement**                                                                                                                                                                                                                                                               | **Tier** | **Ver** |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-026 | The Behaviour Agent shall use an LSTM classifying the last k events of an identity (default k = 20) into benign, scanning, credential stuffing or scraping. Each event: endpoint ID, method, response status class, bucketed time since previous request, authenticated flag. | T1       | T       |
| AI-027 | Per-identity sequences shall be kept in the state store, bounded to 50 events and expiring after 30 min idle.                                                                                                                                                                 | T1       | T       |
| AI-028 | With short history, confidence shall be reduced by the history factor of Section 5.6.                                                                                                                                                                                         | T1       | T       |
| AI-029 | A new identity shall not get a raised score just for being new.                                                                                                                                                                                                               | T1       | T       |
| AI-030 | The agent shall return the transitions or features that mainly drove its score.                                                                                                                                                                                               | T1       | T       |
| AI-031 | The history length available at scoring time shall be recorded.                                                                                                                                                                                                               | T1       | T       |
| AI-072 | A first-order Markov transition model with surprisal scoring shall be kept as a baseline with the same interface, selectable in configuration.                                                                                                                                | T1       | T       |

5.6 Agent confidence (closes OD-02)

| **ID** | **Requirement**                                                                                             | **Tier** | **Ver** |
|--------|-------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-032 | Each agent's confidence shall be a documented deterministic function returning a value in \[0, 1\].         | T1       | I       |
| AI-033 | Confidence shall not depend on the size of the score; an agent can be highly confident a request is benign. | T1       | T       |
| AI-035 | Each agent's confidence shall be checked for calibration on held-out data (FR-112) and the result recorded. | T1       | A       |
| AI-036 | An agent that cannot compute confidence shall return the minimum, never a default maximum.                  | T1       | T       |
| AI-037 | Every confidence value shall be stored in the decision record.                                              | T1       | T       |

| **Agent** | **Confidence formula**                                                                                                                                                                         |
|-----------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Anomaly   | c = 1 − min(1, σ / σ_ref), where σ is the spread of per-tree anomaly scores for the request and σ_ref is the 95th percentile of that spread on validation data. Trees agree → high confidence. |
| Payload   | c = max over classes of softmax(logits / T), with temperature T fitted on validation data.                                                                                                     |
| Behaviour | c = h × p, where h = min(1, history length / 5) and p is the temperature-scaled max softmax probability. A one-event identity gets h = 0.2.                                                    |
| Baselines | n-gram: calibrated max probability. Markov: h × (1 − normalised surprisal variance). Documented in code.                                                                                       |

5.7 Aggregation

Mode A (default): **T = Σᵢ sᵢ·cᵢ·wᵢ / Σᵢ cᵢ·wᵢ** over participating
agents. Mode B: mean of sᵢ. Mode C: share of agents with sᵢ \> 0.5. All
give T in \[0, 1\].

| **ID** | **Requirement**                                                                                     | **Tier** | **Ver** |
|--------|-----------------------------------------------------------------------------------------------------|----------|---------|
| AI-038 | In mode A the decision engine shall compute T with the formula above.                               | T1       | T       |
| AI-039 | T shall always be in \[0, 1\]; a value outside is an internal error.                                | T1       | T       |
| AI-040 | If Σcᵢ·wᵢ \< 10⁻⁶ the engine shall not divide, shall mark "insufficient evidence" and apply FR-036. | T1       | T       |
| AI-041 | Each decision shall record every agent's contribution term and the numerator and denominator.       | T1       | T       |
| AI-042 | T shall be exactly reproducible from the stored scores, confidences and weights.                    | T1       | T       |
| AI-043 | Modes A, B and C shall be selectable in configuration without code changes.                         | T1       | T       |
| AI-045 | Replay shall be able to run all three modes on identical data.                                      | T1       | T       |

5.8 Adaptive weights (closes OD-03, OD-04)

Every N labelled outcomes: perfᵢ = (MCCᵢ + 1) / 2 over the window;
targetᵢ = perfᵢ / mean(perf); wᵢ ← clip((1 − α)·wᵢ + α·targetᵢ, w_min,
w_max), with each change limited to Δ_max.

| **ID** | **Requirement**                                                                                            | **Tier** | **Ver** |
|--------|------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-046 | The weight vector shall be stored in the audit store and survive restarts.                                 | T1       | T       |
| AI-047 | Weights shall stay within \[w_min, w_max\] (defaults 0.1 and 2.0).                                         | T1       | T       |
| AI-048 | All weights shall start at 1.0.                                                                            | T1       | T       |
| AI-049 | Weights shall be recomputed every N new labelled outcomes (default 1 000; demo configuration may use 100). | T1       | T       |
| AI-050 | Per-agent performance shall be measured by MCC rescaled to \[0, 1\].                                       | T1       | T       |
| AI-051 | The update shall use the EMA rule above with α = 0.3 (configurable).                                       | T1       | T       |
| AI-052 | No single update shall change a weight by more than Δ_max (default 0.2).                                   | T1       | T       |
| AI-053 | An update shall be skipped, and the skip recorded, if the window has fewer than 30 positive outcomes.      | T1       | T       |
| AI-054 | Labels shall never be derived from the agents' own outputs or the System's verdicts.                       | T1       | I       |
| AI-055 | Every weight update shall be stored with old weights, new weights, window size, label provenance and time. | T1       | T       |
| AI-056 | An administrator shall be able to freeze weight updates and restore an earlier vector.                     | T2       | T       |

5.9 Training and model lifecycle

| **ID** | **Requirement**                                                                                                                                                                                                                                                    | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| AI-059 | Every model shall be trained on the documented datasets of Section 9, with composition, size, class balance and licence recorded.                                                                                                                                  | T1       | I       |
| AI-061 | Training, validation and test partitions shall be disjoint.                                                                                                                                                                                                        | T1       | I       |
| AI-062 | SR-BH shall be split per class in capture order (first 70% train, next 15% validation, last 15% test), because all SR-BH attacks fall within the first three capture days; generated data shall be split by session; data shall be de-duplicated before splitting. | T1       | I       |
| AI-063 | SSTI and SSRF shall be absent from all training and validation data.                                                                                                                                                                                               | T1       | I       |
| AI-064 | Every trained model file shall carry a version ID.                                                                                                                                                                                                                 | T1       | I       |
| AI-065 | Training shall be reproducible from a script, configuration, seed and dataset version.                                                                                                                                                                             | T1       | T       |
| AI-066 | Model files shall be loaded from the models/ directory, not embedded in code.                                                                                                                                                                                      | T1       | I       |
| AI-069 | Models shall not be retrained during live operation (weight adaptation is not retraining).                                                                                                                                                                         | T1       | I       |
| AI-073 | Hyperparameters shall be tuned on the validation partition only, with a fixed budget (default 20 configurations per model) and every trial logged.                                                                                                                 | T1       | I       |

6\. Explainability Requirements

| **ID**  | **Requirement**                                                                                                 | **Tier** | **Ver** |
|---------|-----------------------------------------------------------------------------------------------------------------|----------|---------|
| XAI-001 | Every decision shall have a structured explanation and a plain-English explanation.                             | T1       | T       |
| XAI-002 | The structured explanation shall list each participating agent with score, confidence, weight and contribution. | T1       | T       |
| XAI-003 | It shall name the agent with the largest contribution.                                                          | T1       | T       |
| XAI-004 | It shall include each agent's evidence (features, tokens, transitions).                                         | T1       | T       |
| XAI-005 | It shall include T, the verdict and the thresholds used.                                                        | T1       | T       |
| XAI-006 | It shall include the attack class, or state that none was determined.                                           | T1       | T       |
| XAI-007 | It shall state the recommended analyst action.                                                                  | T1       | T       |
| XAI-008 | The plain-English text shall explain the verdict without needing model knowledge.                               | T1       | D       |
| XAI-009 | The plain-English text shall be generated deterministically from templates over the structured explanation.     | T1       | T       |
| XAI-010 | For bypass decisions the explanation shall name the checks passed and state that no AI was used.                | T1       | T       |
| XAI-011 | For degraded-mode decisions the explanation shall name the missing agents and why.                              | T1       | T       |
| XAI-013 | No explanation shall state anything not derivable from the decision's recorded values.                          | T1       | I       |
| XAI-016 | The plain-English text shall appear in the dashboard feed; the structured part on opening a decision.           | T1       | D       |
| XAI-017 | No explanation content shall be returned to the API client.                                                     | T1       | T       |
| XAI-020 | SHAP attribution for the Anomaly Agent may be added if the latency budget still holds.                          | T2       | T       |
| XAI-021 | Explanation generation time shall be measured separately.                                                       | T1       | T       |

7\. Non-Functional Requirements

7.1 Performance

**Table 7.1 – Benchmark workload.** Replay of a fixed labelled mix at a
constant rate: 80% benign, 20% attack (even split across Table 5.1), at
least 100 identities in sessions, 5 minutes after a 1-minute warm-up, on
the reference laptop. The rate is set at 60% of the measured saturation
point and then held constant (OD-10).

| **ID**  | **Requirement**                                                                                                         | **Tier** | **Ver** |
|---------|-------------------------------------------------------------------------------------------------------------------------|----------|---------|
| NFR-001 | All performance requirements shall be measured with the workload of Table 7.1 on the reference hardware of Section 2.4. | T1       | A       |
| NFR-002 | Analysis-path processing shall complete within 200 ms at the 95th percentile, excluding demo API time.                  | T1       | T       |
| NFR-003 | Bypass-path processing shall complete within 20 ms at the 95th percentile, excluding demo API time.                     | T1       | T       |
| NFR-004 | Fast filter evaluation shall complete within 5 ms at the 99th percentile.                                               | T1       | T       |
| NFR-005 | Latency shall be reported at p50, p95 and p99, separately for each path.                                                | T1       | T       |
| NFR-006 | Per-stage latency percentiles shall be reported.                                                                        | T1       | T       |
| NFR-009 | The fast-filter clearance share shall be reported as an observation, not treated as a requirement.                      | T1       | D       |
| NFR-010 | Requests shall never be cleared just to meet a latency target.                                                          | T1       | A       |
| NFR-014 | The System shall run on the reference laptop with CPU only and at most 8 GB RAM in use.                                 | T1       | T       |

**Table 7.2 – Planning budget for the analysis path (p95, not binding)**

| **Stage**                               | **Budget**                          |
|-----------------------------------------|-------------------------------------|
| Parsing, features, identity             | ≤ 10 ms                             |
| Fast filter                             | ≤ 5 ms                              |
| Slowest agent (agents run concurrently) | ≤ 120 ms                            |
| Aggregation                             | ≤ 5 ms                              |
| Explanation                             | ≤ 20 ms                             |
| Enforcement and response                | ≤ 10 ms                             |
| Total                                   | ≤ 170 ms against the 200 ms ceiling |

> The budget is looser for the agents than in v1.0 (120 ms vs 90 ms)
> because there is no network hop between agents in v1.1, and tighter
> for explanations (template text only).

7.2 Reliability

| **ID**  | **Requirement**                                                                                                  | **Tier** | **Ver** |
|---------|------------------------------------------------------------------------------------------------------------------|----------|---------|
| NFR-015 | The System shall keep issuing verdicts with any one agent unavailable.                                           | T1       | T       |
| NFR-017 | The System shall keep issuing and enforcing verdicts if the audit store is unavailable, and record the failures. | T1       | T       |
| NFR-020 | Every accepted request shall receive a response or a documented timeout.                                         | T1       | T       |
| NFR-021 | Every call to a dependency (agent, store, demo API) shall have a timeout.                                        | T1       | T       |
| NFR-024 | Separate counters shall exist for agent timeouts, agent errors, aggregation failures and write failures.         | T1       | T       |

7.3 Maintainability

| **ID**  | **Requirement**                                                                                                       | **Tier** | **Ver** |
|---------|-----------------------------------------------------------------------------------------------------------------------|----------|---------|
| NFR-025 | Each component module shall be testable on its own.                                                                   | T1       | I       |
| NFR-026 | Adding a fourth agent shall need no change to the aggregation code.                                                   | T1       | A       |
| NFR-028 | Code shall be kept in a Git repository with branches and pull-request review.                                         | T1       | I       |
| NFR-029 | Unit tests shall cover aggregation, verdict band boundaries, confidence bounds, weight updates and fast filter rules. | T1       | I       |
| NFR-045 | Server code shall be Python only (CON-06).                                                                            | T1       | I       |

7.4 Usability

| **ID**  | **Requirement**                                                                     | **Tier** | **Ver** |
|---------|-------------------------------------------------------------------------------------|----------|---------|
| NFR-031 | An analyst shall be able to see why any decision was made from the dashboard alone. | T1       | D       |
| NFR-034 | A new decision shall appear in the dashboard within 3 s.                            | T1       | T       |
| NFR-035 | The dashboard shall show a clear empty state when no traffic is flowing.            | T1       | D       |

7.5 Auditability and deployment

| **ID**  | **Requirement**                                                                                      | **Tier** | **Ver** |
|---------|------------------------------------------------------------------------------------------------------|----------|---------|
| NFR-036 | Every verdict shall be reconstructible from its stored record.                                       | T1       | T       |
| NFR-037 | Decision records shall be immutable once written.                                                    | T1       | I       |
| NFR-039 | Replay runs shall be reproducible from their recorded configuration and versions.                    | T1       | T       |
| NFR-042 | The complete System, demo API included, shall start with one documented command.                     | T1       | D       |
| NFR-043 | On first start the System shall load trained models, or train them if missing, without manual steps. | T1       | D       |
| NFR-044 | No component shall need a paid licence.                                                              | T1       | I       |

8\. Security Requirements

| **ID**  | **Requirement**                                                                                                     | **Tier** | **Ver** |
|---------|---------------------------------------------------------------------------------------------------------------------|----------|---------|
| SEC-001 | The gateway may terminate TLS. Local demo over HTTP is acceptable and shall be documented as such.                  | T2       | T       |
| SEC-003 | Only the gateway and dashboard ports shall be published; the demo API shall be reachable only from the System.      | T1       | I       |
| SEC-006 | All dashboard pages and /api/\* endpoints shall require login.                                                      | T1       | T       |
| SEC-007 | Administrative operations (reset, configuration, weight freeze) shall require the Administrator role.               | T1       | T       |
| SEC-009 | Passwords shall be stored only as salted, slow one-way hashes (Argon2id or scrypt).                                 | T1       | I       |
| SEC-010 | There shall be no default or hard-coded credentials; initial accounts shall be created from environment variables.  | T1       | I       |
| SEC-011 | Sessions shall expire after 30 minutes idle.                                                                        | T1       | T       |
| SEC-012 | The System shall enforce two roles: Analyst and Administrator.                                                      | T1       | T       |
| SEC-016 | Every login attempt shall be recorded with outcome, source and time.                                                | T1       | T       |
| SEC-022 | Stored payloads shall never be executed or rendered as code anywhere.                                               | T1       | T       |
| SEC-023 | The dashboard shall render payloads, tokens and headers as escaped text.                                            | T1       | T       |
| SEC-025 | End-user credentials used for identity shall be stored only as digests.                                             | T1       | I       |
| SEC-027 | Payloads shall not be written to plain operational logs.                                                            | T1       | I       |
| SEC-028 | Secrets shall come from environment variables or a secrets file excluded from Git.                                  | T1       | I       |
| SEC-029 | Work per request shall be bounded by FR-008, header limits and a processing timeout.                                | T1       | T       |
| SEC-030 | Fast filter regular expressions shall not be prone to catastrophic backtracking.                                    | T1       | I       |
| SEC-033 | Client responses shall not reveal stack traces, component names or versions.                                        | T1       | T       |
| SEC-034 | State-changing dashboard requests shall be protected against CSRF (SameSite=Strict cookie plus token).              | T1       | T       |
| SEC-035 | No request shall reach the demo API without passing through the fast filter.                                        | T1       | T       |
| SEC-037 | Client-supplied identity headers shall not influence behavioural identity unless trusted-proxy mode is on (ADD-32). | T1       | T       |

9\. Data Requirements

9.1 Datasets (closes OD-05)

| **ID** | **Dataset**                                                                                                                                                                                                                               | **Licence**                                  | **Used for**                                                                                                                                    |
|--------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------|
| DS-1   | SR-BH 2020: 907 815 HTTP requests (423 353 after de-duplication), 13 CAPEC labels, full headers and bodies, timestamps. Attacks are scanner-generated (ZAP, Nmap) against a test WordPress site; one internal source IP for all requests. | CC0 1.0                                      | Anomaly training (normal part); payload training (SQLi, command injection, traversal). Not usable for behaviour sequences (no client identity). |
| DS-2   | Team traffic generator (app/traffic.py, extended): authenticated sessions, all Table 5.1 classes, held-out SSTI/SSRF, obfuscated variants                                                                                                 | Team-owned                                   | Behaviour training; XSS and class balance for payload; held-out evaluation                                                                      |
| DS-3   | SecLists and PayloadsAllTheThings                                                                                                                                                                                                         | MIT                                          | Payload seeds for DS-2, one folder per class                                                                                                    |
| DS-4   | CSIC 2010: 61 065 requests, line terminators normalised                                                                                                                                                                                   | Unstated; evaluation only, not redistributed | Cross-corpus test, final evaluation only                                                                                                        |

> Findings after download (13 Oct 2026): 484 460 exact duplicates
> removed; every attack falls on 17–19 July 2020 and later days are
> normal traffic only; labels come from ModSecurity rules and are noisy
> (in a 300-row sample about 70% of SQLi rows contained an obvious SQL
> token). Details and per-split counts are in data/README.md.

9.2 Partitions

| **Partition**   | **Composition**                                                     | **Purpose**                                                     |
|-----------------|---------------------------------------------------------------------|-----------------------------------------------------------------|
| Train           | SR-BH first 70% of each class (capture order) + DS-2 sessions 0–70% | Model fitting                                                   |
| Validation      | SR-BH next 15% of each class + DS-2 sessions 70–85%                 | Tuning, temperature scaling, thresholds, confidence calibration |
| Test            | SR-BH last 15% of each class + DS-2 sessions 85–100%                | Reported main metrics                                           |
| Held-out family | SSTI and SSRF from DS-2                                             | OBJ-5 only                                                      |
| Cross-corpus    | CSIC 2010 (normalised)                                              | Generalisation check, final evaluation only                     |

9.3 Data requirements

| **ID**   | **Requirement**                                                                                                                                                                                                                                                                                                                                                                                                | **Tier** | **Ver** |
|----------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------|---------|
| DATA-001 | Each decision record shall contain: request ID, timestamps, method, path, query, headers (after redaction), payload digest, truncation flag, identity digest and source, rate count, fast filter result and rules, per-agent outputs, aggregation mode, weights, contribution terms, T, thresholds, verdict, attack class, explanation, per-stage timings, model and rule versions, degraded flag, cache flag. | T1       | I       |
| DATA-012 | The System shall store adjudications, weight updates and login events, each with principal and time.                                                                                                                                                                                                                                                                                                           | T1       | I       |
| DATA-013 | Labelled outcomes shall store the true class, provenance (corpus or analyst) and time.                                                                                                                                                                                                                                                                                                                         | T1       | I       |
| DATA-016 | Each decision record shall be identified by its request ID.                                                                                                                                                                                                                                                                                                                                                    | T1       | T       |
| DATA-017 | The stored T shall equal the value recomputed from stored agent outputs, weights and mode.                                                                                                                                                                                                                                                                                                                     | T1       | T       |
| DATA-019 | Decision records shall be write-once.                                                                                                                                                                                                                                                                                                                                                                          | T1       | I       |
| DATA-023 | Every evaluation request shall have a ground-truth label (benign or a Table 5.1 class).                                                                                                                                                                                                                                                                                                                        | T1       | I       |
| DATA-024 | Generated data shall keep session structure and time order.                                                                                                                                                                                                                                                                                                                                                    | T1       | I       |
| DATA-025 | Each dataset shall have a provenance record: source, version, date, processing steps, sample size.                                                                                                                                                                                                                                                                                                             | T1       | I       |
| DATA-026 | The held-out family shall be absent from training and validation (AI-063).                                                                                                                                                                                                                                                                                                                                     | T1       | I       |
| DATA-027 | Only public research corpora under open licences and team-generated data shall be used. Source IPs from SR-BH shall be truncated to /24 or hashed before storage, and no derivative with raw IPs shall be published.                                                                                                                                                                                           | T1       | I       |
| DATA-031 | CSIC 2010 line terminators shall be normalised before use, and the artifact documented.                                                                                                                                                                                                                                                                                                                        | T1       | I       |
| DATA-032 | Data shall be de-duplicated within and across datasets before splitting.                                                                                                                                                                                                                                                                                                                                       | T1       | I       |

9.4 Proposed storage schema (design, not binding)

| **Table**           | **Content**                                                           |
|---------------------|-----------------------------------------------------------------------|
| decisions           | One row per decision; JSON columns for agent results and explanation  |
| adjudications       | Decision ID, analyst, outcome, corrected verdict, justification, time |
| weight_updates      | Old and new weights, window size, metric values, provenance mix, time |
| users / auth_events | Accounts with role and password hash; login attempts                  |
| runs                | Replay run configuration, versions and metrics                        |

10\. External Interfaces

10.1 HTTP endpoints

| **Endpoint**                                | **Purpose**                                                                   | **Access**         |
|---------------------------------------------|-------------------------------------------------------------------------------|--------------------|
| ANY /gateway/{path}                         | Protected entry point; inspected then forwarded to the demo API               | Public             |
| POST /login, POST /logout                   | Dashboard session                                                             | Public / user      |
| GET /                                       | Dashboard page                                                                | Analyst            |
| GET /api/stats                              | Counters, latency, attack breakdown, weights, queue, recent decisions, health | Analyst            |
| GET /api/decisions/{id}                     | Full decision record                                                          | Analyst            |
| GET /api/decisions?filters                  | Historical search (T2)                                                        | Analyst            |
| POST /api/analyze                           | Try-a-request form                                                            | Analyst            |
| POST /api/simulate, POST /api/simulate/stop | Traffic simulator control                                                     | Analyst            |
| POST /api/decisions/{id}/adjudicate         | Adjudication (replaces /api/override)                                         | Analyst            |
| POST /api/reset                             | Clear decisions and weights                                                   | Administrator      |
| GET /health                                 | Component status                                                              | Public (no detail) |

10.2 Interface requirements

| **ID** | **Requirement**                                                                                                    | **Tier** | **Ver** |
|--------|--------------------------------------------------------------------------------------------------------------------|----------|---------|
| UI-003 | The gateway shall return 403 for BLOCK and 429 for rate-limit rejection.                                           | T1       | T       |
| UI-004 | Every response shall include the X-Request-ID header.                                                              | T1       | T       |
| UI-005 | Client responses shall not expose scores, confidences, weights, thresholds, rules, model IDs or explanations.      | T1       | T       |
| UI-009 | All agents shall share one Python interface shape; agent-specific data goes in evidence.                           | T1       | I       |
| UI-022 | Dashboard endpoints and their JSON shapes shall be documented in the repository (README table or OpenAPI file).    | T1       | I       |
| UI-024 | Every dashboard endpoint shall enforce login and role checks.                                                      | T1       | T       |
| UI-030 | Replay shall be runnable from the command line (python evaluate.py --config ...) and write its report to results/. | T1       | T       |

11\. Use Cases

| **ID** | **Use case**                | **Actor**         | **Main flow (short)**                                                                                     | **Key requirements**        |
|--------|-----------------------------|-------------------|-----------------------------------------------------------------------------------------------------------|-----------------------------|
| UC-01  | Normal request              | API client        | Gateway → filter clears → ALLOW → forwarded → record stored                                               | FR-001–028, FR-050, XAI-010 |
| UC-02  | Suspicious request analysed | API client        | Filter refers → 3 agents in parallel → aggregate → verdict → explain → enforce → store                    | FR-031–047, AI-038–043      |
| UC-03  | Threat blocked              | Attacker          | T \> θ₂ → 403, not forwarded, no detail disclosed                                                         | FR-051, FR-052, UI-003      |
| UC-04  | Agent failure               | System            | Agent times out → excluded → degraded decision; all fail → fail-open FLAG                                 | FR-034–036, XAI-011         |
| UC-05  | Monitor dashboard           | Analyst           | Login → live counters, feed, charts → open a decision                                                     | FR-067–077, SEC-006         |
| UC-06  | Review flagged request      | Analyst           | Open queue → inspect → adjudicate with justification → labelled outcome                                   | FR-078–083                  |
| UC-07  | Weights adapt               | System            | N labelled outcomes → MCC per agent → EMA update → audit entry                                            | AI-046–055                  |
| UC-08  | Replay evaluation           | Admin / evaluator | Run evaluate.py with a config → metrics, ablations, baseline comparison, held-out and cross-corpus report | FR-089–097, FR-110–112      |
| UC-09  | Live demo with simulator    | Analyst           | Start mixed traffic with held-out attacks → watch decisions → try a crafted request                       | FR-108, FR-109              |

12\. Verification and Acceptance

12.1 Acceptance criteria

| **ID** | **Criterion**                                                                                                                | **Verifies**             |
|--------|------------------------------------------------------------------------------------------------------------------------------|--------------------------|
| AC-001 | A benign request is forwarded and the demo API's response returned unchanged.                                                | FR-001, FR-050           |
| AC-002 | Every response carries an X-Request-ID that matches the stored record.                                                       | FR-003, UI-004           |
| AC-003 | Each referral rule (signature, rate, unknown endpoint, size bounds) refers a matching request; a clean request is cleared.   | FR-013–020               |
| AC-004 | A signature-matching request is referred even when a cache entry exists.                                                     | FR-017, FR-024           |
| AC-005 | Recorded timings show the three agents running at overlapping times.                                                         | FR-031, FR-038           |
| AC-006 | Every agent returns score and confidence in \[0, 1\] on a test set including empty and malformed inputs.                     | AI-004, AI-005, AI-009   |
| AC-007 | Stored T equals T recomputed from stored values for every decision in a test set.                                            | AI-042, DATA-017         |
| AC-008 | Banding is correct at exactly θ₁, exactly θ₂ and either side.                                                                | FR-042                   |
| AC-009 | The System refuses to start with θ₁ ≥ θ₂.                                                                                    | FR-043                   |
| AC-010 | With one agent disabled, verdicts continue, decisions are marked degraded and explanations name the agent.                   | FR-034, NFR-015, XAI-011 |
| AC-011 | With all agents disabled, requests are forwarded as FLAG and the policy is recorded.                                         | FR-036                   |
| AC-012 | A BLOCK never reaches the demo API (checked in its access log) and the 403 body reveals no detection detail.                 | FR-051, FR-052           |
| AC-013 | Every decision has consistent structured and plain-English explanations.                                                     | XAI-001, XAI-013         |
| AC-014 | A write failure is logged and counted and does not stop enforcement.                                                         | FR-064, NFR-017          |
| AC-015 | Dashboard and API refuse access without login; Analyst cannot call reset.                                                    | SEC-006, SEC-007         |
| AC-016 | An adjudication creates a linked record and leaves the original record byte-identical.                                       | FR-082, NFR-037          |
| AC-017 | Weight updates happen only after N labelled outcomes, respect bounds and Δ_max, skip below 30 positives, and are audited.    | AI-047–055               |
| AC-018 | Two identical replay runs give identical metrics.                                                                            | FR-096                   |
| AC-019 | Replay reports modes A, B, C; each agent disabled in turn; each primary model vs its baseline; held-out and CSIC separately. | FR-092–097, FR-110       |
| AC-020 | Analysis path p95 ≤ 200 ms, bypass p95 ≤ 20 ms and filter p99 ≤ 5 ms under Table 7.1, reported at p50/p95/p99.               | NFR-002–005              |
| AC-021 | Script, SQL and shell payloads display as inert text in the dashboard.                                                       | SEC-022, SEC-023         |
| AC-022 | Spoofed X-User-Id headers do not change the behavioural identity.                                                            | SEC-037                  |
| AC-023 | A fresh machine starts the whole System with one documented command.                                                         | NFR-042, NFR-043         |
| AC-024 | The generator produces labelled sessions for every Table 5.1 class and the held-out family.                                  | FR-105–107, FR-114       |
| AC-025 | No secrets or default passwords are in the repository.                                                                       | SEC-010, SEC-028         |

12.2 Detection acceptance (relative, closes OD-22)

No absolute accuracy number is set before a baseline exists. Instead, on
the identical test partition:

1.  Mode A achieves PR-AUC ≥ mode C (majority vote). If it does not, the
    result is reported honestly as a negative finding.

2.  The three-agent system achieves PR-AUC ≥ any single agent alone.

3.  The system achieves PR-AUC ≥ the fast filter alone (rules-only
    baseline).

4.  CNN and LSTM are compared with their baselines and the result is
    reported either way.

5.  Held-out (SSTI/SSRF) and CSIC results are reported separately with
    no threshold attached.

6.  NFR-002 is met, or the shortfall is reported with the per-stage
    breakdown.

13\. Traceability

| **Objective**                         | **Requirements**                             | **Components**   | **Acceptance**                             |
|---------------------------------------|----------------------------------------------|------------------|--------------------------------------------|
| OBJ-1 Parallel multi-agent detection  | FR-031–039, AI-001–031, AI-070–072           | C-03, C-04, C-05 | AC-005, AC-006, AC-010                     |
| OBJ-2 Confidence-weighted aggregation | FR-040–047, AI-032–056                       | C-06             | AC-007–009, AC-017, AC-019, 12.2 items 1–2 |
| OBJ-3 Latency via fast filter         | FR-013–028, NFR-001–014                      | C-01, C-02, C-08 | AC-003, AC-004, AC-020                     |
| OBJ-4 Explanation for every decision  | FR-057–059, XAI-001–021                      | C-07, C-10       | AC-013                                     |
| OBJ-5 Withheld-family detection       | AI-015–018, AI-063, FR-097, FR-114, DATA-026 | C-03, E-02, E-03 | AC-019, AC-024, 12.2 item 5                |

14\. Risks

| **ID** | **Risk**                                                      | **Impact** | **Likelihood** | **Mitigation**                                                                                           |
|--------|---------------------------------------------------------------|------------|----------------|----------------------------------------------------------------------------------------------------------|
| RSK-01 | SR-BH parsing and cleaning takes longer than planned          | High       | Medium         | Start week 1; use a recorded stratified sample; generator data keeps work moving                         |
| RSK-02 | CNN or LSTM too slow on CPU for 200 ms                        | High       | Low            | Cap input length; small models; baselines can serve live traffic while deep models are evaluated offline |
| RSK-03 | Results on real data much weaker than the synthetic prototype | Medium     | High           | Expected; relative acceptance criteria; report honestly                                                  |
| RSK-04 | Confidence poorly calibrated                                  | High       | Medium         | Temperature scaling; reliability diagrams; modes B and C as fallbacks                                    |
| RSK-05 | Team members cannot explain prototype code in the viva        | High       | Medium         | Code walkthrough in week 1; each module has an owner who presents it                                     |
| RSK-06 | Too few labelled outcomes for weights to move                 | Medium     | Medium         | Replay-driven adaptation; demo N = 100                                                                   |
| RSK-07 | Supervisor rejects deviations from the proposal               | High       | Low            | Present the Scope Deviation Report early; research core unchanged                                        |
| RSK-08 | Mid-evaluation in four weeks leaves LSTM unfinished           | Medium     | Medium         | Markov baseline runs in its place; LSTM shown as in progress                                             |

15\. Open Decisions

v1.0 had 24 open decisions (plus OD-26 raised by the Decision Resolution
report). v1.1 closes all but OD-10, OD-23 and OD-25, and adds two
supervisor items. Closures are recorded in Section 3.4.

| **ID** | **Decision**                                                                                                                | **Owner**          | **When**                           |
|--------|-----------------------------------------------------------------------------------------------------------------------------|--------------------|------------------------------------|
| OD-10  | Declare the reference laptop and set the benchmark rate from a measured baseline                                            | Whole team         | Week 1 (declare), week 3 (measure) |
| OD-23  | Model hyperparameters (protocol fixed by AI-073)                                                                            | AI members         | During training                    |
| OD-25  | Institution, supervisor, roll numbers, submission date                                                                      | Documentation lead | Before submission                  |
| OD-27  | Supervisor confirmation that SR-BH is acceptable (CC0; the file turned out to hold one internal IP, so privacy risk is low) | Documentation lead | Week 1                             |
| OD-28  | Supervisor sign-off on the scope changes in the Scope Deviation Report                                                      | Whole team         | Week 1                             |

Appendix A. Requirement count

| **Category**   | **v1.0** | **v1.1** | **v1.1 T1** | **v1.1 T2** |
|----------------|----------|----------|-------------|-------------|
| Functional     | 107      | 104      | 100         | 4           |
| AI/ML          | 69       | 66       | 65          | 1           |
| Explainability | 21       | 16       | 15          | 1           |
| Non-functional | 44       | 28       | 28          | 0           |
| Security       | 36       | 20       | 19          | 1           |
| Data           | 30       | 13       | 13          | 0           |
| Interface      | 31       | 7        | 7           | 0           |
| Total          | 338      | 254      | 247         | 7           |

v1.1 keeps 254 of the v1.0 requirement count (75%). Removed requirements
mostly served the message broker, multi-service deployment, metrics
stack, configuration-change auditing, inter-service authentication and
the third user role. The full list of withdrawn IDs is in the Scope
Deviation Report.

**End of SRS v1.1**
