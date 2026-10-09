/**
 * Types shared by the run pipeline.
 */

/** What a run needs to execute. Carries no credential. */
export interface RunJob {
  readonly run_id: string;
  readonly hunt_id: string;
  readonly tenant_id: string;
  readonly provider: string;
  readonly repos: readonly string[];
  /**
   * The public Git URL this hunt targets, from `scope.repo`, or null. White-box
   * discovery reads this repository's source; a hunt with no repository in scope
   * is refused at intake (there is nothing to analyse yet).
   */
  readonly repoUrl: string | null;
  /** The declared scope. The sandbox egress allowlist is compiled from it. */
  readonly scope: Record<string, unknown>;
  readonly depth: string;
  readonly policy: Record<string, unknown>;
}

/**
 * The AI-facing configuration the child needs to make model calls, forwarded by
 * the parent at run start. This is the one thing besides the job that crosses
 * into the child, and it crosses over IPC rather than through the environment:
 * the child's environment is empty so a crash dump or a `/proc` read cannot
 * harvest it, and so it stays scoped to the run that was handed it rather than
 * being ambient for anything that runs in the process.
 */
export interface RunCredentials {
  readonly aiProvider: "matterai" | "clef";
  readonly aiBaseUrl: string;
  readonly aiApiKey: string;
  readonly attackerModel: string;
  readonly verifierModel: string;
  readonly judgeModel: string;
  readonly verifyN: number;
  readonly costPer1kTokensUsd: number;
  /** Per-run token budget; the agent stops exploring once it is spent. */
  readonly maxRunTokens: number;
  /** Which runtime drives the generator stages: the built-in agent, or orbcode. */
  readonly agentRuntime: "internal" | "orbcode";
  /** Path to the orbcode launcher, when `agentRuntime` is "orbcode". */
  readonly orbcodeBin: string;
  /** Which backend decides the JEV gates: the LLM, or GLiNER2.5-Decide. */
  readonly judgeProvider: "chat" | "gliner";
  /** Base URL of the GLiNER2.5-Decide service, when `judgeProvider` is "gliner". */
  readonly judgeBaseUrl: string;
}

/**
 * Which brokered tools this run may offer the agent. The child advertises only the
 * ones that are actually available (a container runtime for `bash`, a search key for
 * `web_search`); it never runs them itself — it asks the parent over IPC.
 */
export interface RunCapabilities {
  readonly bash: boolean;
  readonly webSearch: boolean;
}

/** What the forked child is started with. */
export interface RunInput {
  readonly job: RunJob;
  readonly credentials: RunCredentials;
  /** Which brokered tools the parent can service for this run. */
  readonly capabilities: RunCapabilities;
  /**
   * Absolute path to the already-cloned repository, or null. The parent clones
   * (it can spawn `git` and reach the network); the child only reads, with
   * `--allow-fs-read` extended to this directory. The child never clones and never
   * executes a line of the repository's code — it reads source as text and reasons
   * about it, which is what keeps white-box analysis off the egress-boundary path.
   */
  readonly repoDir: string | null;
  /**
   * URL of the scoped egress proxy, or null. When set, the child routes all
   * HTTP/HTTPS traffic through this proxy, which enforces the declared scope.
   */
  readonly proxyUrl: string | null;
}

export type RunStatus = "queued" | "running" | "completed" | "failed" | "stopped";

export type Level = "debug" | "info" | "warn" | "error";

/** A log line. */
export interface RunEvent {
  readonly level: Level;
  readonly stage: string;
  readonly message: string;
  readonly ts: string;
}

/**
 * One JEV gate's decision (HUNTER-PLAN.md §3.0, §3.3).
 *
 * A generator proposes; a judge decides, in this exact shape, so a verdict is
 * auditable and comparable across gates and runs rather than free-form prose.
 */
export interface JevVerdict {
  readonly gate: string;
  readonly verdict: "success" | "partial" | "inconclusive" | "fail";
  readonly confidence: number;
  readonly evidence_refs: readonly string[];
  readonly rationale: string;
  readonly next: "verify" | "iterate" | "falsify" | "drop";
}

/** A synthesised attack hypothesis, before it is run against the target. */
export interface Hypothesis {
  /** Human-facing handle, e.g. `H-001`. Unique within a run. */
  readonly code: string;
  readonly target: string;
  readonly predicted_class?: "A" | "B" | "C" | "D" | undefined;
  readonly rationale: string;
}

/** A promoted finding. */
export interface Finding {
  readonly title: string;
  readonly severity: "critical" | "high" | "medium" | "low";
  readonly novelty_class?: "A" | "B" | "C" | "D";
  readonly cwe?: string;
  readonly owasp?: string;
  readonly repro_ratio?: string;
  /** The hypothesis this finding was promoted from, by its run-local code. */
  readonly hypothesis_code?: string;
  /** How the flaw works — the mechanism an attacker exploits. */
  readonly mechanism?: string;
  /** Where it lives, as `path:line` references into the analysed repository. */
  readonly location?: string;
  /** The precise remediation guidance (a PR is a later layer). */
  readonly remediation?: string;
  /** The specific code/evidence the verdict was grounded in. */
  readonly evidence?: string;
}

/**
 * What the isolated child tells its parent. The child holds no ambient
 * credential — only the run-scoped `RunCredentials` it was started with — and
 * makes no write calls to the control plane; it reports and the parent writes.
 */
export type ChildMessage =
  | { readonly type: "stage"; readonly name: string }
  | { readonly type: "event"; readonly event: RunEvent }
  | { readonly type: "hypothesis"; readonly hypothesis: Hypothesis }
  | {
      readonly type: "hypothesis_status";
      readonly code: string;
      readonly status: "queued" | "verifying" | "exploiting" | "exploited" | "confirmed" | "falsified" | "dropped";
    }
  | {
      readonly type: "verdict";
      readonly gate: string;
      readonly hypothesis_code?: string | undefined;
      readonly verdict: JevVerdict;
    }
  | { readonly type: "finding"; readonly finding: Finding }
  | { readonly type: "spend"; readonly usd: number }
  /** A privileged tool the child cannot run itself; the parent executes and replies. */
  | {
      readonly type: "tool_request";
      readonly id: string;
      readonly tool: "bash" | "web_search";
      readonly args: Record<string, unknown>;
    }
  | { readonly type: "done"; readonly ok: boolean; readonly reason?: string };

/** What the parent sends down to the child: the answer to a brokered tool request. */
export type ParentMessage = {
  readonly type: "tool_response";
  readonly id: string;
  readonly result: string;
};
