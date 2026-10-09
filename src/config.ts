/**
 * Configuration, read once from the environment.
 *
 * Hunter runs on GCP and connects to Redis directly. It reaches D1 through the
 * gateway worker, and the worker reaches Hunter, with one shared secret between
 * them. It calls out to one more place: an inference gateway (matterai.so) for
 * the attacker, verifier, and judge model calls.
 *
 * Required: `REDIS_URL`, `HUNTER_SECRET`, `MATTERAI_API_KEY`, `ATTACKER_MODEL`,
 * `VERIFIER_MODEL`, `JUDGE_MODEL`. Missing AI configuration does not crash the
 * service — it fails each run closed at the start of its pipeline with a clear
 * reason, so a misconfigured deploy is visible per-run rather than down entirely.
 */

/** Which inference gateway a run's model calls go through. */
export type AiProvider = "matterai" | "clef";

export interface Config {
  readonly port: number;
  readonly redisUrl: string;
  /** The gateway worker, which lends D1 and is the only caller of this service. */
  readonly workerUrl: string;
  /** The one shared secret: the worker presents it to us and we present it back. */
  readonly secret: string;
  /** Redis stream the run queue lives on. */
  readonly queueName: string;
  /** How many runs execute at once. */
  readonly concurrency: number;
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
  /** Per-run token budget; the agent stops exploring once it is spent. */
  readonly maxRunTokens: number;
  /** Generator runtime: the built-in agent, or the orbcode harness. */
  readonly agentRuntime: "internal" | "orbcode";
  /** Path to the orbcode launcher (bin/orbcode.js) when agentRuntime is "orbcode". */
  readonly orbcodeBin: string;
  /** JEV judge backend: the LLM ("chat"), or GLiNER2.5-Decide ("gliner"). */
  readonly judgeProvider: "chat" | "gliner";
  /** GLiNER2.5-Decide base URL when judgeProvider is "gliner". */
  readonly judgeBaseUrl: string;

  // --- Tools -------------------------------------------------------------
  // `bash` only runs inside an isolated container, so it is off unless a runtime
  // is configured. `web_search` is off unless a Fireworks key is set. Both are
  // disabled by default so nothing runs on the host and no key is assumed.

  /** `none` (bash disabled) or `docker`. */
  readonly sandboxRuntime: "none" | "docker";
  /** Container image a run's bash executes in. */
  readonly sandboxImage: string;
  /** OCI runtime, e.g. `runsc` for gVisor; empty for the Docker default. */
  readonly sandboxOciRuntime: string;
  /** Fireworks web-search key and base URL. Empty key disables web_search. */
  readonly fireworksApiKey: string;
  readonly fireworksBaseUrl: string;
}

const DEFAULT_PORT = 8080;
const DEFAULT_CONCURRENCY = 2;
const DEFAULT_RUN_TIMEOUT_MS = 30 * 60_000;
const DEFAULT_VERIFY_N = 3;
const DEFAULT_AI_BASE_URL = "https://api2.matterai.so/v1";
const DEFAULT_COST_PER_1K_TOKENS_USD = 0.002;
const DEFAULT_MAX_RUN_TOKENS = 1_500_000;
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
    redisUrl: process.env.REDIS_URL ?? "redis://127.0.0.1:6379",
    workerUrl: (process.env.WORKER_URL ?? "https://api.frostwolf.app").replace(/\/$/, ""),
    secret: process.env.HUNTER_SECRET ?? "",
    queueName: process.env.QUEUE_NAME ?? "hunter-runs",
    concurrency: intFromEnv("CONCURRENCY", DEFAULT_CONCURRENCY),
    runTimeoutMs: intFromEnv("RUN_TIMEOUT_MS", DEFAULT_RUN_TIMEOUT_MS),

    aiProvider: process.env.MODEL_PROVIDER === "clef" ? "clef" : "matterai",
    aiBaseUrl: process.env.MATTERAI_BASE_URL ?? DEFAULT_AI_BASE_URL,
    aiApiKey: process.env.MATTERAI_API_KEY ?? "",
    attackerModel: process.env.ATTACKER_MODEL ?? "",
    verifierModel: process.env.VERIFIER_MODEL ?? "",
    judgeModel: process.env.JUDGE_MODEL ?? "",
    verifyN: intFromEnv("VERIFY_N", DEFAULT_VERIFY_N),
    costPer1kTokensUsd: floatFromEnv("COST_PER_1K_TOKENS_USD", DEFAULT_COST_PER_1K_TOKENS_USD),
    maxRunTokens: intFromEnv("MAX_RUN_TOKENS", DEFAULT_MAX_RUN_TOKENS),
    agentRuntime: process.env.AGENT_RUNTIME === "orbcode" ? "orbcode" : "internal",
    orbcodeBin: process.env.ORBCODE_BIN ?? "",
    judgeProvider: process.env.JUDGE_PROVIDER === "gliner" ? "gliner" : "chat",
    judgeBaseUrl: process.env.JUDGE_BASE_URL ?? "",

    sandboxRuntime: process.env.SANDBOX_RUNTIME === "docker" ? "docker" : "none",
    sandboxImage: process.env.SANDBOX_IMAGE ?? "node:22-slim",
    sandboxOciRuntime: process.env.SANDBOX_OCI_RUNTIME ?? "",
    fireworksApiKey: process.env.FIREWORKS_API_KEY ?? "",
    fireworksBaseUrl: process.env.FIREWORKS_BASE_URL ?? DEFAULT_FIREWORKS_BASE_URL,
  };
}
