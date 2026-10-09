-- FrostWolf Hunter — the autonomous red-teaming product's system of record.
--
-- D1 is the one database. Hunter is a separate service that reaches it through the
-- gateway worker's generic `/internal/d1` endpoint, so the worker holds no Hunter
-- logic and this schema is Hunter's alone. Apply it once with:
--
--   cd frostwolf-worker && npx wrangler d1 execute frostwolf --remote \
--     --file ../frostwolf-hunter-engine/migrations/0001_hunter.sql
--
-- Every statement is idempotent, so applying it again is harmless. Redis holds the
-- run queue and the live log; everything durable is here.

-- Conventions follow the existing schema: TEXT primary keys, ISO-8601 TEXT
-- timestamps, structured data in JSON TEXT columns, tenant-scoped indexes, and
-- digests rather than secrets. Hunter stores no provider credential at all: the
-- engine holds its own Git tokens, so nothing here is worth stealing.

-- A customer's connected provider and the scope it exposes.
--
-- `repos_json` and `runtime_json` record what was connected; `scope_json` on a
-- hunt is the authoritative allowlist. A revoked
-- connection keeps its row so historical runs still resolve, and is filtered by
-- `revoked_at IS NULL` on the read path exactly as `api_keys` is.
CREATE TABLE IF NOT EXISTS hunter_connections (
  id              TEXT PRIMARY KEY,
  tenant_id       TEXT NOT NULL,
  provider        TEXT NOT NULL,              -- github | gitlab | bitbucket
  repos_json      TEXT NOT NULL DEFAULT '[]',
  runtime_json    TEXT NOT NULL DEFAULT '{}',
  created_at      TEXT NOT NULL,
  revoked_at      TEXT
);

CREATE INDEX IF NOT EXISTS idx_hunter_connections_tenant
  ON hunter_connections (tenant_id, created_at DESC);

-- A hunt: a connection plus a scope and a policy, run once or continuously.
--
-- `scope_json` is the declared scope that the sandbox egress allowlist is
-- compiled from — the blocking invariant of the product lives here. `status`
-- tracks the hunt's own lifecycle (a continuous hunt is `active` between runs);
-- an individual execution's state lives on `hunter_runs`.
CREATE TABLE IF NOT EXISTS hunter_hunts (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  connection_id TEXT NOT NULL,
  mode          TEXT NOT NULL DEFAULT 'oneshot',   -- oneshot | continuous
  scope_json    TEXT NOT NULL DEFAULT '{}',
  depth         TEXT NOT NULL DEFAULT 'standard',
  policy_json   TEXT NOT NULL DEFAULT '{}',
  status        TEXT NOT NULL DEFAULT 'idle',       -- idle | active | stopped
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_hunts_tenant
  ON hunter_hunts (tenant_id, created_at DESC);

-- One execution of a hunt.
--
-- `tenant_id` is denormalised onto the run (and onto the tables below it) so a
-- tenant-scoped read and the per-event writeback are a single predicate rather
-- than a join back to `hunter_hunts` on every live event. `status` is the state
-- the engine reports as the state machine advances:
-- queued -> running -> completed | failed | stopped.
CREATE TABLE IF NOT EXISTS hunter_runs (
  id               TEXT PRIMARY KEY,
  hunt_id          TEXT NOT NULL,
  tenant_id        TEXT NOT NULL,
  status           TEXT NOT NULL DEFAULT 'queued',
  stage            TEXT,                              -- current state-machine stage
  started_at       TEXT,
  finished_at      TEXT,
  graph_stats_json TEXT,
  cost_usd         REAL NOT NULL DEFAULT 0,
  model_usage_json TEXT,
  created_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_runs_hunt ON hunter_runs (hunt_id);
CREATE INDEX IF NOT EXISTS idx_hunter_runs_tenant
  ON hunter_runs (tenant_id, created_at DESC);

-- The hypothesis ledger: one synthesised attack idea per row.
--
-- `code` is the human-facing handle (`H-001`). `status` is the ledger lifecycle:
-- queued -> verifying -> confirmed | falsified | dropped.
CREATE TABLE IF NOT EXISTS hunter_hypotheses (
  id              TEXT PRIMARY KEY,
  run_id          TEXT NOT NULL,
  tenant_id       TEXT NOT NULL,
  code            TEXT NOT NULL,
  target          TEXT,
  predicted_class TEXT,                               -- A | B | C | D
  rationale       TEXT,
  status          TEXT NOT NULL DEFAULT 'queued',
  created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_hypotheses_run
  ON hunter_hypotheses (run_id, status);

-- A promoted finding: a flaw that was executed and independently reproduced.
--
-- `poc_ref` points at the PoC artifact in object storage rather than inlining
-- it. `repro_ratio` records the N/N independent-verification result that gated
-- promotion. `status` is the triage lifecycle the console drives:
-- open -> confirmed | dismissed | fixed.
CREATE TABLE IF NOT EXISTS hunter_findings (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  hunt_id       TEXT NOT NULL,
  run_id        TEXT NOT NULL,
  hypothesis_id TEXT,
  title         TEXT NOT NULL,
  cwe           TEXT,
  owasp         TEXT,
  severity      TEXT NOT NULL,                        -- critical | high | medium | low
  novelty_class TEXT,                                 -- A | B | C | D
  poc_ref       TEXT,
  repro_ratio   TEXT,                                 -- e.g. "10/10"
  chain_json    TEXT,
  status        TEXT NOT NULL DEFAULT 'open',
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_findings_tenant
  ON hunter_findings (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_hunter_findings_run
  ON hunter_findings (run_id);

-- A remediation attached to a finding: the PR and the re-verification result.
CREATE TABLE IF NOT EXISTS hunter_remediations (
  id             TEXT PRIMARY KEY,
  finding_id     TEXT NOT NULL,
  tenant_id      TEXT NOT NULL,
  pr_url         TEXT,
  branch         TEXT,
  patch_ref      TEXT,
  test_ref       TEXT,
  reverify_ratio TEXT,                                -- must reach "0/N" to pass
  status         TEXT NOT NULL DEFAULT 'proposed',
  created_at     TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_remediations_finding
  ON hunter_remediations (finding_id);

-- The durable tail of the live log.
--
-- The live stream itself is Redis pub/sub; only a tail is persisted here so a
-- run's log survives after Redis has expired the channel. High-volume live
-- chatter stays in Redis — this table is the audit record, not the transport.
CREATE TABLE IF NOT EXISTS hunter_events (
  id        TEXT PRIMARY KEY,
  run_id    TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  ts        TEXT NOT NULL,
  level     TEXT NOT NULL DEFAULT 'info',             -- debug | info | warn | error
  stage     TEXT,
  message   TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_events_run ON hunter_events (run_id, ts);

-- Per-tenant, per-period usage. The cost driver is compute, not request count,
-- so the metered units are the ones a customer values and that cost money:
-- verifications and PRs, with GPU-seconds underneath. `period` is `YYYY-MM` in
-- UTC, matching `usage_counters`.
CREATE TABLE IF NOT EXISTS hunter_usage (
  tenant_id     TEXT NOT NULL,
  period        TEXT NOT NULL,
  hunts         INTEGER NOT NULL DEFAULT 0,
  verifications INTEGER NOT NULL DEFAULT 0,
  gpu_seconds   INTEGER NOT NULL DEFAULT 0,
  prs           INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (tenant_id, period)
);
