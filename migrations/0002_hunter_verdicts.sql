-- Every JEV gate's decision, persisted so a promoted finding carries a full,
-- auditable trail from synthesis to verdict (HUNTER-PLAN.md §3.4: "Everything a
-- JEV decides is persisted").
--
-- `hypothesis_id` is null for a gate that judges the run as a whole (the Scope
-- Judge) rather than one hypothesis. `evidence_json` is the judge's own cited
-- evidence references, never the raw target response — that lives only in the
-- live log and the run's durable event tail.

CREATE TABLE IF NOT EXISTS hunter_verdicts (
  id            TEXT PRIMARY KEY,
  run_id        TEXT NOT NULL,
  tenant_id     TEXT NOT NULL,
  hypothesis_id TEXT,
  gate          TEXT NOT NULL,
  verdict       TEXT NOT NULL,          -- success | partial | inconclusive | fail
  confidence    REAL NOT NULL,
  evidence_json TEXT NOT NULL DEFAULT '[]',
  rationale     TEXT NOT NULL,
  next          TEXT NOT NULL,          -- verify | iterate | falsify | drop
  created_at    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_hunter_verdicts_run ON hunter_verdicts (run_id, created_at);
