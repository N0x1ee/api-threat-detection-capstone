-- Audit database (PostgreSQL). Created by the XAI service on start; safe to run twice.
CREATE TABLE IF NOT EXISTS decisions (
    id              BIGSERIAL PRIMARY KEY,
    request_id      TEXT UNIQUE NOT NULL,
    ts              DOUBLE PRECISION NOT NULL,
    route           TEXT NOT NULL,              -- ai | fast_filter | rate_limit
    verdict         TEXT NOT NULL,              -- ALLOW | FLAG | BLOCK
    score           DOUBLE PRECISION,           -- NULL = insufficient evidence / not analysed
    attack_type     TEXT,
    mode            TEXT,
    degraded        BOOLEAN DEFAULT FALSE,
    policy_used     TEXT,
    method          TEXT,
    path            TEXT,
    query           TEXT,
    ip              TEXT,
    identity        TEXT,
    identity_source TEXT,
    rule_ids        JSONB,
    rules_version   TEXT,
    agents          JSONB,                      -- per agent: score, confidence, weight, detail
    excluded        JSONB,
    thresholds      JSONB,
    numerator       DOUBLE PRECISION,
    denominator     DOUBLE PRECISION,
    explanation     JSONB,                      -- summary, evidence, action, structured
    timings_ms      JSONB,
    created_at      TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS decisions_ts ON decisions (ts DESC);
CREATE INDEX IF NOT EXISTS decisions_verdict ON decisions (verdict);

CREATE TABLE IF NOT EXISTS adjudications (
    id                BIGSERIAL PRIMARY KEY,
    request_id        TEXT NOT NULL REFERENCES decisions (request_id),
    ts                DOUBLE PRECISION NOT NULL,
    analyst           TEXT NOT NULL,
    outcome           TEXT NOT NULL CHECK (outcome IN ('malicious', 'benign', 'undetermined')),
    justification     TEXT NOT NULL,
    corrected_verdict TEXT CHECK (corrected_verdict IN ('ALLOW', 'FLAG', 'BLOCK'))
);

CREATE TABLE IF NOT EXISTS weight_updates (
    id        BIGSERIAL PRIMARY KEY,
    ts        DOUBLE PRECISION NOT NULL,
    skipped   BOOLEAN,
    entry     JSONB NOT NULL
);
