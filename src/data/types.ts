/**
 * Wire types for FrostWolf Hunter.
 *
 * These describe the JSON the console and the CLI exchange with `/v1/hunter/*`,
 * and the JSON the engine writes back through `/internal/hunter/*`. As with the
 * Guard wire types in `../types.ts`, nothing here reveals how detection works:
 * the engine decides what a flaw is on the GCP side, and the control plane only
 * records the verdicts and serves them back.
 */

/** Risk level of a finding. */
export type Severity = "critical" | "high" | "medium" | "low";

/** Lifecycle of a single hunt execution, as the engine advances it. */
export type RunStatus = "queued" | "running" | "completed" | "failed" | "stopped";

/** Lifecycle of the hunt itself, independent of any one run. */
export type HuntStatus = "idle" | "active" | "stopped";

/** How a hunt is scheduled. */
export type HuntMode = "oneshot" | "continuous";

/** Triage lifecycle of a promoted finding, as the console drives it. */
export type FindingStatus = "open" | "confirmed" | "dismissed" | "fixed";

/** Novelty class the Novelty Judge assigns. */
export type NoveltyClass = "A" | "B" | "C" | "D";

/** Severity of a live log line. */
export type EventLevel = "debug" | "info" | "warn" | "error";

/** A connected provider, as the customer surface returns it (never the credential). */
export interface ConnectionView {
  readonly id: string;
  readonly provider: string;
  readonly repos: readonly string[];
  readonly runtime: Record<string, unknown>;
  readonly created_at: string;
  readonly revoked: boolean;
}

/** A hunt, as the customer surface returns it. */
export interface HuntView {
  readonly id: string;
  readonly connection_id: string;
  readonly mode: HuntMode;
  readonly scope: Record<string, unknown>;
  readonly depth: string;
  readonly status: HuntStatus;
  readonly created_at: string;
}

/** A run, as the customer surface returns it. */
export interface RunView {
  readonly id: string;
  readonly hunt_id: string;
  readonly status: RunStatus;
  readonly stage: string | null;
  readonly started_at: string | null;
  readonly finished_at: string | null;
  readonly cost_usd: number;
  readonly created_at: string;
}

/** A finding, as the customer surface returns it. */
export interface FindingView {
  readonly id: string;
  readonly hunt_id: string;
  readonly run_id: string;
  readonly title: string;
  readonly severity: Severity;
  readonly novelty_class: NoveltyClass | null;
  readonly cwe: string | null;
  readonly owasp: string | null;
  readonly repro_ratio: string | null;
  readonly status: FindingStatus;
  /** How the flaw works. */
  readonly mechanism: string | null;
  /** `path:line` references into the analysed repository. */
  readonly location: string | null;
  /** Precise remediation guidance. */
  readonly remediation: string | null;
  /** The code the verdict was grounded in. */
  readonly evidence: string | null;
  readonly created_at: string;
}

/** One line of a run's log, as the console polls it. */
export interface EventView {
  /** Monotonic cursor: pass the last one seen as `after` to get only newer lines. */
  readonly seq: number;
  readonly ts: string;
  readonly level: EventLevel;
  readonly stage: string | null;
  readonly message: string;
}

// The writeback types below are the engine's parse boundary: their optional
// fields are filled from best-effort coercion of raw JSON, so a field is
// genuinely `value-or-undefined` rather than merely absent. They are annotated
// with explicit `| undefined` so that coerced value flows through under
// `exactOptionalPropertyTypes` without a conditional-spread at every call site.

/** A log line the engine writes back as a run advances. */
export interface EventWriteback {
  readonly level?: EventLevel | undefined;
  readonly stage?: string | undefined;
  readonly message: string;
  /** When the event occurred on the engine, ISO-8601. Defaults to receipt time. */
  readonly ts?: string | undefined;
}

/** A status transition the engine writes back as the state machine advances. */
export interface RunStatusWriteback {
  readonly status: RunStatus;
  readonly stage?: string | undefined;
  readonly cost_usd?: number | undefined;
  readonly graph_stats?: Record<string, unknown> | undefined;
  readonly model_usage?: Record<string, unknown> | undefined;
}

/** A finding the engine promotes and writes back. */
export interface FindingWriteback {
  readonly run_id: string;
  readonly hypothesis_id?: string | undefined;
  readonly title: string;
  readonly severity: Severity;
  readonly novelty_class?: NoveltyClass | undefined;
  readonly cwe?: string | undefined;
  readonly owasp?: string | undefined;
  readonly poc_ref?: string | undefined;
  readonly repro_ratio?: string | undefined;
  readonly chain?: unknown;
  readonly mechanism?: string | undefined;
  readonly location?: string | undefined;
  readonly remediation?: string | undefined;
  readonly evidence?: string | undefined;
}

/** A usage increment the engine meters as it spends. */
export interface UsageWriteback {
  readonly hunts?: number | undefined;
  readonly verifications?: number | undefined;
  readonly gpu_seconds?: number | undefined;
  readonly prs?: number | undefined;
}

/** A hypothesis the attacker brain synthesised, written back as it is proposed. */
export interface HypothesisWriteback {
  /** Human-facing handle, e.g. `H-001`. Unique within the run. */
  readonly code: string;
  readonly target?: string | undefined;
  readonly predicted_class?: NoveltyClass | undefined;
  readonly rationale?: string | undefined;
}

/** A hypothesis's ledger status, as `HUNTER-PLAN.md` §5 defines it. */
export type HypothesisStatus = "queued" | "verifying" | "exploiting" | "exploited" | "confirmed" | "falsified" | "dropped";

/** One JEV gate's decision, written back for the audit trail (§3.0, §3.4). */
export interface VerdictWriteback {
  readonly run_id: string;
  /** The hypothesis this verdict is about, by its run-local code. Absent for a run-level gate. */
  readonly hypothesis_code?: string | undefined;
  readonly gate: string;
  readonly verdict: "success" | "partial" | "inconclusive" | "fail";
  readonly confidence: number;
  readonly evidence_refs: readonly string[];
  readonly rationale: string;
  readonly next: "verify" | "iterate" | "falsify" | "drop";
}
