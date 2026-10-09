/**
 * Hunter's data access.
 *
 * Every query is tenant-scoped in SQL, so a row from another tenant can never be
 * returned by a missing JavaScript check. The database is D1, reached through the
 * gateway worker (`../d1.ts`). Hunter stores no provider credential: it holds its
 * own Git tokens.
 */

import { randomBytes } from "node:crypto";
import type { Db } from "../d1.js";
import type { RunJob } from "../types.js";
import type {
  ConnectionView,
  EventWriteback,
  EventView,
  Severity,
  FindingView,
  FindingWriteback,
  HuntView,
  HypothesisStatus,
  HypothesisWriteback,
  NoveltyClass,
  RunStatusWriteback,
  RunView,
  UsageWriteback,
  VerdictWriteback,
} from "./types.js";

/** Everything the data layer needs: the database. */
export interface Env {
  readonly DB: Db;
}

/** A short, prefixed id in the shape the rest of the control plane uses. */
function id(prefix: string): string {
  return `${prefix}_${randomBytes(16).toString("base64url")}`;
}

/** The calendar month a moment falls in, as `YYYY-MM` in UTC. */
function periodOf(at: Date): string {
  return at.toISOString().slice(0, 7);
}

// --- Connections -----------------------------------------------------------

/** What a connection is created from. */
export interface NewConnection {
  readonly provider: string;
  readonly repos: readonly string[];
  readonly runtime: Record<string, unknown>;
}

/** Create a connection. */
export async function createConnection(
  env: Env,
  tenantId: string,
  input: NewConnection,
): Promise<ConnectionView> {
  const connectionId = id("conn");
  const createdAt = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO hunter_connections
       (id, tenant_id, provider, repos_json, runtime_json, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)`,
  )
    .bind(
      connectionId,
      tenantId,
      input.provider,
      JSON.stringify(input.repos),
      JSON.stringify(input.runtime),
      createdAt,
    )
    .run();

  return {
    id: connectionId,
    provider: input.provider,
    repos: input.repos,
    runtime: input.runtime,
    created_at: createdAt,
    revoked: false,
  };
}

/** A connection row as D1 returns it. */
interface ConnectionRow {
  readonly id: string;
  readonly provider: string;
  readonly repos_json: string;
  readonly runtime_json: string;
  readonly created_at: string;
  readonly revoked_at: string | null;
}

/** List a tenant's connections, newest first. */
export async function listConnections(
  env: Env,
  tenantId: string,
): Promise<ConnectionView[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, provider, repos_json, runtime_json, created_at, revoked_at
       FROM hunter_connections
      WHERE tenant_id = ?1
      ORDER BY created_at DESC`,
  )
    .bind(tenantId)
    .all<ConnectionRow>();

  return results.map(toConnectionView);
}

/** Revoke a connection. Returns false when the tenant has no such live row. */
export async function revokeConnection(
  env: Env,
  tenantId: string,
  connectionId: string,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE hunter_connections SET revoked_at = ?1
      WHERE id = ?2 AND tenant_id = ?3 AND revoked_at IS NULL`,
  )
    .bind(new Date().toISOString(), connectionId, tenantId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}

function toConnectionView(row: ConnectionRow): ConnectionView {
  return {
    id: row.id,
    provider: row.provider,
    repos: parseArray(row.repos_json),
    runtime: parseObject(row.runtime_json),
    created_at: row.created_at,
    revoked: row.revoked_at !== null,
  };
}

// --- Hunts -----------------------------------------------------------------

/** What a hunt is created from. */
export interface NewHunt {
  readonly connection_id: string;
  readonly mode: "oneshot" | "continuous";
  readonly scope: Record<string, unknown>;
  readonly depth: string;
  readonly policy: Record<string, unknown>;
}

/** A hunt row as D1 returns it. */
interface HuntRow {
  readonly id: string;
  readonly connection_id: string;
  readonly mode: string;
  readonly scope_json: string;
  readonly depth: string;
  readonly status: string;
  readonly created_at: string;
}

/** Create a hunt against a connection the tenant owns. */
export async function createHunt(
  env: Env,
  tenantId: string,
  input: NewHunt,
): Promise<HuntView | null> {
  // A hunt may only reference a live connection the tenant owns, checked in SQL
  // so a forged connection id cannot attach a hunt to another tenant's repo.
  const connection = await env.DB.prepare(
    `SELECT id FROM hunter_connections
      WHERE id = ?1 AND tenant_id = ?2 AND revoked_at IS NULL LIMIT 1`,
  )
    .bind(input.connection_id, tenantId)
    .first<{ id: string }>();

  if (connection === null) {
    return null;
  }

  const huntId = id("hunt");
  const createdAt = new Date().toISOString();

  await env.DB.prepare(
    `INSERT INTO hunter_hunts
       (id, tenant_id, connection_id, mode, scope_json, depth, policy_json,
        status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'idle', ?8)`,
  )
    .bind(
      huntId,
      tenantId,
      input.connection_id,
      input.mode,
      JSON.stringify(input.scope),
      input.depth,
      JSON.stringify(input.policy),
      createdAt,
    )
    .run();

  return {
    id: huntId,
    connection_id: input.connection_id,
    mode: input.mode,
    scope: input.scope,
    depth: input.depth,
    status: "idle",
    created_at: createdAt,
  };
}

/** List a tenant's hunts, newest first. */
export async function listHunts(env: Env, tenantId: string): Promise<HuntView[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, connection_id, mode, scope_json, depth, status, created_at
       FROM hunter_hunts
      WHERE tenant_id = ?1
      ORDER BY created_at DESC`,
  )
    .bind(tenantId)
    .all<HuntRow>();

  return results.map(toHuntView);
}

/** Fetch one hunt the tenant owns, or null. */
export async function getHunt(
  env: Env,
  tenantId: string,
  huntId: string,
): Promise<HuntView | null> {
  const row = await env.DB.prepare(
    `SELECT id, connection_id, mode, scope_json, depth, status, created_at
       FROM hunter_hunts
      WHERE id = ?1 AND tenant_id = ?2 LIMIT 1`,
  )
    .bind(huntId, tenantId)
    .first<HuntRow>();

  return row === null ? null : toHuntView(row);
}

function toHuntView(row: HuntRow): HuntView {
  return {
    id: row.id,
    connection_id: row.connection_id,
    mode: row.mode === "continuous" ? "continuous" : "oneshot",
    scope: parseObject(row.scope_json),
    depth: row.depth,
    status: toHuntStatus(row.status),
    created_at: row.created_at,
  };
}

// --- Runs ------------------------------------------------------------------

/** A run row as D1 returns it. */
interface RunRow {
  readonly id: string;
  readonly hunt_id: string;
  readonly status: string;
  readonly stage: string | null;
  readonly started_at: string | null;
  readonly finished_at: string | null;
  readonly cost_usd: number;
  readonly created_at: string;
}

/**
 * Start a run of a hunt: write a `queued` run and mark the hunt active.
 *
 * The run row is the durable record the engine advances through writeback. It is
 * created here, in D1, rather than in the queue, so a run exists the moment it is
 * requested whether or not the engine has picked it up yet. Enqueueing the job is
 * the caller's next step and is best-effort: a run that is never dequeued simply
 * stays `queued`, which is the honest state.
 */
export async function startRun(
  env: Env,
  tenantId: string,
  huntId: string,
): Promise<RunView | null> {
  const hunt = await getHunt(env, tenantId, huntId);
  if (hunt === null) {
    return null;
  }

  const runId = id("run");
  const createdAt = new Date().toISOString();

  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO hunter_runs
         (id, hunt_id, tenant_id, status, created_at)
       VALUES (?1, ?2, ?3, 'queued', ?4)`,
    ).bind(runId, huntId, tenantId, createdAt),
    env.DB.prepare(
      `UPDATE hunter_hunts SET status = 'active' WHERE id = ?1 AND tenant_id = ?2`,
    ).bind(huntId, tenantId),
  ]);

  return {
    id: runId,
    hunt_id: huntId,
    status: "queued",
    stage: null,
    started_at: null,
    finished_at: null,
    cost_usd: 0,
    created_at: createdAt,
  };
}

/** Mark a hunt stopped and stop its unfinished runs. Returns false when absent. */
export async function stopHunt(
  env: Env,
  tenantId: string,
  huntId: string,
): Promise<boolean> {
  const hunt = await getHunt(env, tenantId, huntId);
  if (hunt === null) {
    return false;
  }

  const now = new Date().toISOString();
  await env.DB.batch([
    env.DB.prepare(
      `UPDATE hunter_hunts SET status = 'stopped' WHERE id = ?1 AND tenant_id = ?2`,
    ).bind(huntId, tenantId),
    env.DB.prepare(
      `UPDATE hunter_runs SET status = 'stopped', finished_at = ?1
        WHERE hunt_id = ?2 AND tenant_id = ?3
          AND status IN ('queued', 'running')`,
    ).bind(now, huntId, tenantId),
  ]);

  return true;
}

/** List the runs of a hunt the tenant owns, newest first. */
export async function listRuns(
  env: Env,
  tenantId: string,
  huntId: string,
): Promise<RunView[]> {
  const { results } = await env.DB.prepare(
    `SELECT id, hunt_id, status, stage, started_at, finished_at, cost_usd, created_at
       FROM hunter_runs
      WHERE hunt_id = ?1 AND tenant_id = ?2
      ORDER BY created_at DESC`,
  )
    .bind(huntId, tenantId)
    .all<RunRow>();

  return results.map(toRunView);
}

/** Fetch one run the tenant owns, or null. */
export async function getRun(
  env: Env,
  tenantId: string,
  runId: string,
): Promise<RunView | null> {
  const row = await env.DB.prepare(
    `SELECT id, hunt_id, status, stage, started_at, finished_at, cost_usd, created_at
       FROM hunter_runs
      WHERE id = ?1 AND tenant_id = ?2 LIMIT 1`,
  )
    .bind(runId, tenantId)
    .first<RunRow>();

  return row === null ? null : toRunView(row);
}

function toRunView(row: RunRow): RunView {
  return {
    id: row.id,
    hunt_id: row.hunt_id,
    status: toRunStatus(row.status),
    stage: row.stage,
    started_at: row.started_at,
    finished_at: row.finished_at,
    cost_usd: row.cost_usd,
    created_at: row.created_at,
  };
}

// --- Findings --------------------------------------------------------------

/** A finding row as D1 returns it. */
interface FindingRow {
  readonly id: string;
  readonly hunt_id: string;
  readonly run_id: string;
  readonly title: string;
  readonly severity: string;
  readonly novelty_class: string | null;
  readonly cwe: string | null;
  readonly owasp: string | null;
  readonly repro_ratio: string | null;
  readonly status: string;
  readonly mechanism: string | null;
  readonly location: string | null;
  readonly remediation: string | null;
  readonly evidence: string | null;
  readonly created_at: string;
}

/** The finding columns both reads select. */
const FINDING_COLUMNS =
  "id, hunt_id, run_id, title, severity, novelty_class, cwe, owasp, repro_ratio, " +
  "status, mechanism, location, remediation, evidence, created_at";

/** List a tenant's findings, newest first. */
export async function listFindings(
  env: Env,
  tenantId: string,
): Promise<FindingView[]> {
  const { results } = await env.DB.prepare(
    `SELECT ${FINDING_COLUMNS}
       FROM hunter_findings
      WHERE tenant_id = ?1
      ORDER BY created_at DESC`,
  )
    .bind(tenantId)
    .all<FindingRow>();

  return results.map(toFindingView);
}

/** Fetch one finding the tenant owns, or null. */
export async function getFinding(
  env: Env,
  tenantId: string,
  findingId: string,
): Promise<FindingView | null> {
  const row = await env.DB.prepare(
    `SELECT ${FINDING_COLUMNS}
       FROM hunter_findings
      WHERE id = ?1 AND tenant_id = ?2 LIMIT 1`,
  )
    .bind(findingId, tenantId)
    .first<FindingRow>();

  return row === null ? null : toFindingView(row);
}

/** Set a finding's triage status. Returns false when the tenant has no such row. */
export async function setFindingStatus(
  env: Env,
  tenantId: string,
  findingId: string,
  status: FindingView["status"],
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE hunter_findings SET status = ?1 WHERE id = ?2 AND tenant_id = ?3`,
  )
    .bind(status, findingId, tenantId)
    .run();

  return (result.meta.changes ?? 0) > 0;
}

function toFindingView(row: FindingRow): FindingView {
  return {
    id: row.id,
    hunt_id: row.hunt_id,
    run_id: row.run_id,
    title: row.title,
    severity: toSeverity(row.severity),
    novelty_class: toNoveltyClass(row.novelty_class),
    cwe: row.cwe,
    owasp: row.owasp,
    repro_ratio: row.repro_ratio,
    status: toFindingStatus(row.status),
    mechanism: row.mechanism,
    location: row.location,
    remediation: row.remediation,
    evidence: row.evidence,
    created_at: row.created_at,
  };
}

// --- Engine writeback ------------------------------------------------------

/** The tenant a run belongs to, or null when the run is unknown. */
async function tenantOfRun(env: Env, runId: string): Promise<string | null> {
  const row = await env.DB.prepare(
    `SELECT tenant_id FROM hunter_runs WHERE id = ?1 LIMIT 1`,
  )
    .bind(runId)
    .first<{ tenant_id: string }>();
  return row === null ? null : row.tenant_id;
}

/**
 * Append a batch of events to a run's log.
 *
 * The run is looked up to resolve its tenant and to prove it exists, so the
 * engine cannot write events against a run that is not there. The engine batches
 * its log lines, so one request is one D1 batch rather than one write per line.
 * Returns false when the run is unknown.
 */
export async function appendEvents(
  env: Env,
  runId: string,
  events: readonly EventWriteback[],
): Promise<boolean> {
  const tenantId = await tenantOfRun(env, runId);
  if (tenantId === null) {
    return false;
  }

  if (events.length === 0) {
    return true;
  }

  const statement = env.DB.prepare(
    `INSERT INTO hunter_events (id, run_id, tenant_id, ts, level, stage, message)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)`,
  );
  const now = new Date().toISOString();

  await env.DB.batch(
    events.map((event) =>
      statement.bind(
        id("evt"),
        runId,
        tenantId,
        event.ts ?? now,
        event.level ?? "info",
        event.stage ?? null,
        event.message,
      ),
    ),
  );

  return true;
}

/** How many events one poll returns at most. */
const EVENT_PAGE = 200;

/**
 * A run's log, oldest first, starting after a cursor.
 *
 * The cursor is the `seq` of the last event the caller saw, so a poll returns only
 * what is new. `seq` is the table's rowid, which only grows.
 */
export async function listEvents(
  env: Env,
  tenantId: string,
  runId: string,
  after: number,
): Promise<EventView[]> {
  const { results } = await env.DB.prepare(
    `SELECT rowid AS seq, ts, level, stage, message
       FROM hunter_events
      WHERE run_id = ?1 AND tenant_id = ?2 AND rowid > ?3
      ORDER BY rowid
      LIMIT ?4`,
  )
    .bind(runId, tenantId, after, EVENT_PAGE)
    .all<EventView>();

  return results;
}

/**
 * Advance a run's status.
 *
 * Sets `started_at` on the first transition to `running` and `finished_at` on any
 * terminal transition, so the timeline is recorded without the engine having to
 * send timestamps. Returns false when the run is unknown.
 */
export async function updateRunStatus(
  env: Env,
  runId: string,
  update: RunStatusWriteback,
): Promise<boolean> {
  const tenantId = await tenantOfRun(env, runId);
  if (tenantId === null) {
    return false;
  }

  const now = new Date().toISOString();
  const terminal =
    update.status === "completed" ||
    update.status === "failed" ||
    update.status === "stopped";

  const result = await env.DB.prepare(
    `UPDATE hunter_runs
        SET status = ?1,
            stage = COALESCE(?2, stage),
            cost_usd = COALESCE(?3, cost_usd),
            graph_stats_json = COALESCE(?4, graph_stats_json),
            model_usage_json = COALESCE(?5, model_usage_json),
            started_at = CASE WHEN ?1 = 'running' AND started_at IS NULL
                              THEN ?6 ELSE started_at END,
            finished_at = CASE WHEN ?7 = 1 THEN ?6 ELSE finished_at END
      WHERE id = ?8`,
  )
    .bind(
      update.status,
      update.stage ?? null,
      update.cost_usd ?? null,
      update.graph_stats === undefined ? null : JSON.stringify(update.graph_stats),
      update.model_usage === undefined ? null : JSON.stringify(update.model_usage),
      now,
      terminal ? 1 : 0,
      runId,
    )
    .run();

  const updated = (result.meta.changes ?? 0) > 0;
  if (updated && terminal) {
    // A hunt is `active` while any run is in flight; the last run to finish hands
    // it back. A stopped hunt stays stopped, and a hunt with another run still
    // queued or running stays active.
    await env.DB.prepare(
      `UPDATE hunter_hunts SET status = 'idle'
        WHERE status = 'active'
          AND id = (SELECT hunt_id FROM hunter_runs WHERE id = ?1)
          AND NOT EXISTS (
            SELECT 1 FROM hunter_runs
             WHERE hunt_id = hunter_hunts.id AND status IN ('queued', 'running')
          )`,
    )
      .bind(runId)
      .run();
  }

  return updated;
}

/** Record a promoted finding. Returns the new id, or null when the run is unknown. */
export async function insertFinding(
  env: Env,
  finding: FindingWriteback,
): Promise<string | null> {
  const run = await env.DB.prepare(
    `SELECT tenant_id, hunt_id FROM hunter_runs WHERE id = ?1 LIMIT 1`,
  )
    .bind(finding.run_id)
    .first<{ tenant_id: string; hunt_id: string }>();

  if (run === null) {
    return null;
  }

  const findingId = id("find");
  await env.DB.prepare(
    `INSERT INTO hunter_findings
       (id, tenant_id, hunt_id, run_id, hypothesis_id, title, cwe, owasp,
        severity, novelty_class, poc_ref, repro_ratio, chain_json, status,
        mechanism, location, remediation, evidence, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, 'open',
             ?14, ?15, ?16, ?17, ?18)`,
  )
    .bind(
      findingId,
      run.tenant_id,
      run.hunt_id,
      finding.run_id,
      finding.hypothesis_id ?? null,
      finding.title,
      finding.cwe ?? null,
      finding.owasp ?? null,
      finding.severity,
      finding.novelty_class ?? null,
      finding.poc_ref ?? null,
      finding.repro_ratio ?? null,
      finding.chain === undefined ? null : JSON.stringify(finding.chain),
      finding.mechanism ?? null,
      finding.location ?? null,
      finding.remediation ?? null,
      finding.evidence ?? null,
      new Date().toISOString(),
    )
    .run();

  return findingId;
}

/**
 * Resolve a hypothesis's database id from its run-local code (`H-001`).
 *
 * The code is what the sandboxed child knows; the id is what a foreign key
 * needs. Null when the run has no hypothesis under that code.
 */
export async function resolveHypothesisId(
  env: Env,
  runId: string,
  code: string,
): Promise<string | null> {
  const row = await env.DB.prepare(
    `SELECT id FROM hunter_hypotheses WHERE run_id = ?1 AND code = ?2 LIMIT 1`,
  )
    .bind(runId, code)
    .first<{ id: string }>();
  return row === null ? null : row.id;
}

/**
 * Record a hypothesis the attacker brain proposed. Returns the new id, or null
 * when the run is unknown.
 */
export async function insertHypothesis(
  env: Env,
  runId: string,
  input: HypothesisWriteback,
): Promise<string | null> {
  const tenantId = await tenantOfRun(env, runId);
  if (tenantId === null) {
    return null;
  }

  const hypothesisId = id("hyp");
  await env.DB.prepare(
    `INSERT INTO hunter_hypotheses
       (id, run_id, tenant_id, code, target, predicted_class, rationale, status, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'queued', ?8)`,
  )
    .bind(
      hypothesisId,
      runId,
      tenantId,
      input.code,
      input.target ?? null,
      input.predicted_class ?? null,
      input.rationale ?? null,
      new Date().toISOString(),
    )
    .run();

  return hypothesisId;
}

/** Advance a hypothesis's ledger status. Returns false when it is unknown. */
export async function setHypothesisStatus(
  env: Env,
  runId: string,
  code: string,
  status: HypothesisStatus,
): Promise<boolean> {
  const result = await env.DB.prepare(
    `UPDATE hunter_hypotheses SET status = ?1 WHERE run_id = ?2 AND code = ?3`,
  )
    .bind(status, runId, code)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/**
 * Record one JEV gate's decision (HUNTER-PLAN.md §3.4: every verdict is
 * persisted). Returns false when the run is unknown.
 */
export async function insertVerdict(env: Env, input: VerdictWriteback): Promise<boolean> {
  const tenantId = await tenantOfRun(env, input.run_id);
  if (tenantId === null) {
    return false;
  }

  const hypothesisId =
    input.hypothesis_code === undefined
      ? null
      : await resolveHypothesisId(env, input.run_id, input.hypothesis_code);

  await env.DB.prepare(
    `INSERT INTO hunter_verdicts
       (id, run_id, tenant_id, hypothesis_id, gate, verdict, confidence,
        evidence_json, rationale, next, created_at)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)`,
  )
    .bind(
      id("verdict"),
      input.run_id,
      tenantId,
      hypothesisId,
      input.gate,
      input.verdict,
      input.confidence,
      JSON.stringify(input.evidence_refs),
      input.rationale,
      input.next,
      new Date().toISOString(),
    )
    .run();

  return true;
}

/**
 * Meter the usage of a run's tenant for the current period.
 *
 * The run resolves the tenant, so the engine never names one — a writeback can
 * only meter the tenant the run belongs to. Increments by column, so one
 * writeback can record a verification without disturbing the PR count. Upserts on
 * `(tenant_id, period)` like `usage_counters`. Returns false when the run is
 * unknown.
 */
export async function incrementUsage(
  env: Env,
  runId: string,
  usage: UsageWriteback,
): Promise<boolean> {
  const tenantId = await tenantOfRun(env, runId);
  if (tenantId === null) {
    return false;
  }

  const period = periodOf(new Date());
  await env.DB.prepare(
    `INSERT INTO hunter_usage (tenant_id, period, hunts, verifications, gpu_seconds, prs)
     VALUES (?1, ?2, ?3, ?4, ?5, ?6)
     ON CONFLICT (tenant_id, period) DO UPDATE SET
       hunts = hunts + excluded.hunts,
       verifications = verifications + excluded.verifications,
       gpu_seconds = gpu_seconds + excluded.gpu_seconds,
       prs = prs + excluded.prs`,
  )
    .bind(
      tenantId,
      period,
      usage.hunts ?? 0,
      usage.verifications ?? 0,
      usage.gpu_seconds ?? 0,
      usage.prs ?? 0,
    )
    .run();

  return true;
}

// --- Parsing helpers -------------------------------------------------------

function parseArray(value: string): string[] {
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

function parseObject(value: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(value) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : {};
  } catch {
    return {};
  }
}

function toRunStatus(value: string): RunView["status"] {
  switch (value) {
    case "running":
    case "completed":
    case "failed":
    case "stopped":
      return value;
    default:
      return "queued";
  }
}

function toHuntStatus(value: string): HuntView["status"] {
  return value === "active" || value === "stopped" ? value : "idle";
}

function toFindingStatus(value: string): FindingView["status"] {
  switch (value) {
    case "confirmed":
    case "dismissed":
    case "fixed":
      return value;
    default:
      return "open";
  }
}

function toSeverity(value: string): Severity {
  switch (value) {
    case "critical":
    case "high":
    case "low":
      return value;
    default:
      return "medium";
  }
}

function toNoveltyClass(value: string | null): NoveltyClass | null {
  return value === "A" || value === "B" || value === "C" || value === "D"
    ? value
    : null;
}

// --- Run execution ---------------------------------------------------------

/**
 * What a run needs to execute: its hunt's scope and its connection's repos.
 *
 * Returns null when the run is unknown or its connection was revoked since it was
 * queued, so a revoked connection's run never starts.
 */
export async function getRunJob(env: Env, runId: string): Promise<RunJob | null> {
  const row = await env.DB.prepare(
    `SELECT r.id, r.hunt_id, r.tenant_id, h.scope_json, h.depth, h.policy_json,
            c.provider, c.repos_json, c.revoked_at
       FROM hunter_runs r
       JOIN hunter_hunts h ON h.id = r.hunt_id
       JOIN hunter_connections c ON c.id = h.connection_id
      WHERE r.id = ?1 LIMIT 1`,
  )
    .bind(runId)
    .first<{
      id: string;
      hunt_id: string;
      tenant_id: string;
      scope_json: string;
      depth: string;
      policy_json: string;
      provider: string;
      repos_json: string;
      revoked_at: string | null;
    }>();

  if (row === null || row.revoked_at !== null) {
    return null;
  }

  const scope = parseObject(row.scope_json);
  const repo = scope.repo;

  return {
    run_id: row.id,
    hunt_id: row.hunt_id,
    tenant_id: row.tenant_id,
    provider: row.provider,
    repos: parseArray(row.repos_json),
    repoUrl: typeof repo === "string" && repo.length > 0 ? repo : null,
    scope,
    depth: row.depth,
    policy: parseObject(row.policy_json),
  };
}

/** Whether a run was stopped from the console while it was executing. */
export async function isRunStopped(env: Env, runId: string): Promise<boolean> {
  const row = await env.DB.prepare(`SELECT status FROM hunter_runs WHERE id = ?1 LIMIT 1`)
    .bind(runId)
    .first<{ status: string }>();
  return row !== null && row.status === "stopped";
}
