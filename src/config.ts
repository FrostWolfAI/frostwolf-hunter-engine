/**
 * Configuration, read once from the environment.
 *
 * Hunter is one HTTP service. It reaches D1 through the gateway worker, and the
 * worker reaches Hunter, with one shared secret between them. It calls out to one
 * more place: an inference gateway (matterai.so) for the attacker, verifier, and
 * judge model calls. No queue, no Redis — a hunt is started by a direct API call.
 *
 * Required: `HUNTER_SECRET`, `MATTERAI_API_KEY`, `ATTACKER_MODEL`,
 * `VERIFIER_MODEL`, `JUDGE_MODEL`. Missing AI configuration does not crash the
 * service — it fails each run closed at the start of its pipeline with a clear
 * reason, so a misconfigured deploy is visible per-run rather than down entirely.
 */

import { resolveOrbcodeBin } from "./orbcode-bin.js";

/** Which inference gateway a run's model calls go through. */
export type AiProvider = "matterai" | "clef";

export interface Config {
  readonly port: number;
  /** The gateway worker, which lends D1 and is the only caller of this service. */
  readonly workerUrl: string;
  /** The one shared secret: the worker presents it to us and we present it back. */
  readonly secret: string;
  /** Wall-clock budget for one run's child process, in milliseconds. */
  readonly runTimeoutMs: number;

  // --- Model inference ---------------------------------------------------
  // Clef (Cloudflare's model) is not live yet; selecting it fails clearly rather
  // than guessing at a contract that does not exist. matterai.so is the only
  // provider that actually answers today, and model ids are configuration, never
  // hardcoded, per HUNTER-PLAN.md §4b.

  readonly aiProvider: AiProvider;
  readonly aiBaseUrl: string;
  readonly aiApiKey: string;
  /** Attacker brain: invents and drives the probe. */
  readonly attackerModel: string;
  /** Verifier brain: independently reproduces, on a different model. */
  readonly verifierModel: string;
  /** The JEV judge tier: cheap, low-temperature, structured verdicts only. */
  readonly judgeModel: string;
  /** How many independent reproductions a success needs before it is promoted. */
  readonly verifyN: number;
  /** Rough cost estimate, pending real billing data from matterai.so. */
  readonly costPer1kTokensUsd: number;
  /**
   * Generator runtime. `orbcode` (the DEFAULT) drives the orbcode harness;
   * `claude`/`codex` are reserved for those agents and fail clearly until wired;
   * `internal` is the built-in loop, kept for tests only. A real run uses orbcode.
   */
  readonly agentRuntime: "orbcode" | "claude" | "codex" | "internal";
  /** Path to the orbcode launcher (bin/orbcode.js). Required when agentRuntime is "orbcode". */
  readonly orbcodeBin: string;
  /**
   * JEV judge backend: `skip` (no judge call — the default while the judge is
   * being reworked), the LLM (`chat`), or GLiNER2.5-Decide (`gliner`).
   */
  readonly judgeProvider: "skip" | "chat" | "gliner";
  /** GLiNER2.5-Decide base URL when judgeProvider is "gliner". */
  readonly judgeBaseUrl: string;

  // --- Tools -------------------------------------------------------------
  // `bash` always runs inside an isolated container — never the host, and never
  // disabled. The image and OCI runtime are configurable; the sandbox itself is
  // not optional. `web_search` is off unless a Fireworks key is set.

  /** Container image a run's bash executes in. */
  readonly sandboxImage: string;
  /** OCI runtime, e.g. `runsc` for gVisor; empty for the Docker default. */
  readonly sandboxOciRuntime: string;
  /** Fireworks web-search key and base URL. Empty key disables web_search. */
  readonly fireworksApiKey: string;
  readonly fireworksBaseUrl: string;
}

const DEFAULT_PORT = 6888;
const DEFAULT_RUN_TIMEOUT_MS = 4 * 60 * 60_000;
const DEFAULT_VERIFY_N = 1;
const DEFAULT_AI_BASE_URL = "https://api2.matterai.so/v1";
const DEFAULT_COST_PER_1K_TOKENS_USD = 0.002;
const DEFAULT_FIREWORKS_BASE_URL = "https://api.fireworks.ai";

function intFromEnv(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function floatFromEnv(name: string, fallback: number): number {
  const parsed = Number.parseFloat(process.env[name] ?? "");
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function loadConfig(): Config {
  return {
    port: intFromEnv("PORT", DEFAULT_PORT),
    workerUrl: (process.env.WORKER_URL ?? "https://api.frostwolf.app").replace(/\/$/, ""),
    secret: process.env.HUNTER_SECRET ?? "",
    runTimeoutMs: intFromEnv("RUN_TIMEOUT_MS", DEFAULT_RUN_TIMEOUT_MS),

    aiProvider: process.env.MODEL_PROVIDER === "clef" ? "clef" : "matterai",
    aiBaseUrl: process.env.MATTERAI_BASE_URL ?? DEFAULT_AI_BASE_URL,
    aiApiKey: process.env.MATTERAI_API_KEY ?? "",
    attackerModel: process.env.ATTACKER_MODEL ?? "",
    verifierModel: process.env.VERIFIER_MODEL ?? "",
    judgeModel: process.env.JUDGE_MODEL ?? "",
    verifyN: intFromEnv("VERIFY_N", DEFAULT_VERIFY_N),
    costPer1kTokensUsd: floatFromEnv("COST_PER_1K_TOKENS_USD", DEFAULT_COST_PER_1K_TOKENS_USD),
    agentRuntime:
      process.env.AGENT_RUNTIME === "internal"
        ? "internal"
        : process.env.AGENT_RUNTIME === "claude"
          ? "claude"
          : process.env.AGENT_RUNTIME === "codex"
            ? "codex"
            : "orbcode",
    // Resolved to an absolute, existing path (or "" when not found) once at boot,
    // portably across OSes. A sandboxed run child cannot touch the filesystem to
    // check, so the parent settles this here.
    orbcodeBin: resolveOrbcodeBin(process.env.ORBCODE_BIN),
    judgeProvider:
      process.env.JUDGE_PROVIDER === "gliner"
        ? "gliner"
        : process.env.JUDGE_PROVIDER === "chat"
          ? "chat"
          : "skip",
    judgeBaseUrl: process.env.JUDGE_BASE_URL ?? "",

    sandboxImage: process.env.SANDBOX_IMAGE ?? "node:22-slim",
    sandboxOciRuntime: process.env.SANDBOX_OCI_RUNTIME ?? "",
    fireworksApiKey: process.env.FIREWORKS_API_KEY ?? "",
    fireworksBaseUrl: process.env.FIREWORKS_BASE_URL ?? DEFAULT_FIREWORKS_BASE_URL,
  };
}
