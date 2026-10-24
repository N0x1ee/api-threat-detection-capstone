# Adaptive Multi-Agent & Explainable AI System for Real-Time API Threat Detection

MCA final-year capstone project.
👥 Project Team
Thapar Institute of Engineering & Technology, Patiala, India  |
Department of Computer Science and Engineering  |
Supervisor: Dr. Surjit Singh, Department of Computer Science & Engineering, Thapar Institute of Engineering & Technology, Patiala, India  |
Email: surjit.singh@thapar.edu  |
| Member | Role |
|---|---|
| NOxiee | AI / ML (payload agent, data pipeline), documentation lead |
| Sehaj | AI / ML (behaviour and anomaly agents, evaluation) |
| Navjot | Gateway, demo API, dashboard, authentication, deployment |
| Shrey | Documentation, testing, cross-functional support |

## What it is

The System sits in front of an HTTP API and checks every request:

1. A rule-based **fast filter** clears ordinary traffic in well under a millisecond.
2. Suspicious requests go to **three AI agents in parallel**: anomaly (Isolation Forest), payload and behaviour.
3. A **decision engine** combines their scores, weighting each agent by its confidence and its recent measured accuracy.
4. Each request ends as **ALLOW**, **FLAG** (forwarded, plus an analyst review) or **BLOCK**.
5. Every decision gets a **plain-English explanation** on an authenticated dashboard.

## Where things are

```
api-threat-detection/   the working system (Python/Flask): gateway, agents, decision engine,
                        dashboard, demo shop API, evaluation, tests  -> see its README
data/                   dataset scripts, processed datasets, payload seed lists -> see data/README.md
docs/                   SRS v1.1, Scope Deviation Report, Progress Report (Word)
docs/history/           the same documents as Markdown, plus the document timeline
references/             project proposal, system-flow diagram, the two reference papers
legacy/                 the original July agent scripts and the 8 Oct prototype, untouched, for comparison
```

## Run it

```
cd api-threat-detection
pip install -r requirements.txt
python run.py                                   # first run asks you to create an admin account
python -m unittest discover -s tests -t .       # 58 tests
python evaluate.py                              # replay evaluation -> results/
```

## Status (14 Oct 2026)

- **Done:** the scope was adapted to what four people can deliver (SRS v1.1).
- **Data:** SR-BH 2020 is downloaded and cleaned, and the payload seed corpus is built.
- **Code:** the decision engine, evaluation, gateway, demo API, login and Docker files are rebuilt to the SRS.
- **Still to do:** CNN payload agent, LSTM behaviour agent, the SRS confidence formulas, CSIC 2010 cross-test, adjudication records.

The full account, including what does not work yet and which results did not hold up, is in `docs/Progress_Report_2026-10-14.docx`.

## How this was built (transparency)

- **The 8 October prototype** (`legacy/prototype_2026-10-08_original.zip`) was generated with AI assistance in a single session.
- **Planning, documentation and code changes since 9 October** were done with Claude (Anthropic) in Cowork, directed and reviewed by the team.
- **The Progress Report** lists what was produced this way and what each member needs to understand before the viva.
- **The research decisions** (scope, models, data, evaluation design) were made by the team and are recorded in the SRS.

## Data and licences

- **SR-BH 2020:** CC0 1.0, doi:10.7910/DVN/OGOIXX.
- **Payload seeds:** from PayloadsAllTheThings and SecLists, both MIT; the licence files are in `data/seeds/`.
- **CSIC 2010:** used for evaluation only and not stored in this repository.
- **Reference papers** in `references/`: © their publishers, included for private team use. Remove them before making this repository public.
- **Attack strings** in this repository are only for training and testing a detector in our own test setup. Never send them to systems you do not own.
