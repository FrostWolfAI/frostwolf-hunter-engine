/**
 * The run state machine.
 *
 * A run is an explicit sequence of stages rather than one free-running agent, so
 * each stage is checkpointed, cost-capped, and swappable: a stage is a name and a
 * `run`, and the sequence is an array. A stage returns `ok` or a refusal, and a
 * refusal stops the machine. Stage 0's scope check is the one refusal gate today;
 * everything else a stage decides about its own hypothesis goes through a judge
 * and is recorded with `verdict`, rather than stopping the whole run.
 *
 * The machine runs inside the isolated child, so it only reports: every method on
 * the context is a message to the parent, which owns every connection (Redis, D1,
 * and — for the parent's own bookkeeping — nothing else; model and target calls
 * are made from inside the child, through `client` and `fetch`, both scoped to
 * this one run).
 */

import type { Judge } from "./judge.js";
import type { ModelClient } from "./models/types.js";
import type { Explorer } from "./orbcode.js";
import type { Toolset } from "./tools.js";
import type { Finding, Hypothesis, JevVerdict, Level, RunCredentials, RunJob } from "./types.js";

export type StageOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: string };

/** What a stage can do. Every call is relayed to the parent except the model and target calls. */
export interface RunContext {
  readonly job: RunJob;
  /** The cloned repository on disk, read-only, or null when none is in scope. */
  readonly repoDir: string | null;
  /** Model names, verification budget, and cost rate for this run. Never the raw credentials. */
  readonly models: Pick<
    RunCredentials,
    "attackerModel" | "verifierModel" | "judgeModel" | "verifyN" | "costPer1kTokensUsd"
  >;
  /** The one model client for this run, already built from the run's provider. */
  readonly client: ModelClient;
  /** A `fetch` that refuses anything outside the declared scope. See `scope.ts`. */
  readonly fetch: typeof fetch;
  /** The agent's tool belt: read_file/list_dir/search, plus bash/web_search when available. */
  readonly tools: Toolset;
  /**
   * Run a generator task — recon, synthesis, independent re-derivation. Backed by
   * either the built-in agent loop or the orbcode substrate, chosen per deployment.
   * The judges below are never routed through this; deciding stays Hunter's.
   */
  readonly explore: Explorer;
  /**
   * Adjudicate a stage: a generator proposes, this decides. Backed by the LLM
   * (default) or a structured decision model (GLiNER2.5-Decide), per deployment.
   */
  readonly judge: Judge;
  /** A per-run scratch pad stages use to pass state forward (e.g. the live hypothesis). */
  readonly scratch: Record<string, unknown>;
  /** The per-run token budget guard; the agent stops exploring once it is exceeded. */
  readonly budget: { add(tokens: number): void; exceeded(): boolean };
  emit(level: Level, stage: string, message: string): void;
  hypothesis(hypothesis: Hypothesis): void;
  hypothesisStatus(code: string, status: "queued" | "verifying" | "exploiting" | "exploited" | "confirmed" | "falsified" | "dropped"): void;
  verdict(gate: string, hypothesisCode: string | undefined, verdict: JevVerdict): void;
  promote(finding: Finding): void;
  spend(usd: number): void;
}

export interface Stage {
  readonly name: string;
  run(ctx: RunContext): Promise<StageOutcome>;
}

export interface MachineResult {
  readonly status: "completed" | "failed";
  readonly refusedAt?: string;
  readonly reason?: string;
}

/** Run the stages in order, stopping at the first refusal. */
export async function runStages(
  ctx: RunContext,
  stages: readonly Stage[],
  enter: (stage: string) => void,
): Promise<MachineResult> {
  for (const stage of stages) {
    enter(stage.name);
    const outcome = await stage.run(ctx);
    if (!outcome.ok) {
      ctx.emit("error", stage.name, `refused: ${outcome.reason}`);
      return { status: "failed", refusedAt: stage.name, reason: outcome.reason };
    }
  }
  return { status: "completed" };
}
