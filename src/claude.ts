/**
 * Claude Code (`claude`) as Hunter's generator runtime.
 *
 * Drives the `claude` CLI headlessly (`-p --output-format json --bare`) with:
 *   - Explicit Base URL override (`ANTHROPIC_BASE_URL`, normalized so `/v1/messages`
 *     is not doubled when `MATTERAI_BASE_URL` ends with `/v1`)
 *   - Explicit API Key override (`ANTHROPIC_API_KEY` + `ANTHROPIC_AUTH_TOKEN`)
 *   - Explicit Model override (`--model <model>` + `ANTHROPIC_MODEL` + tier defaults)
 *   - Dangerous permissions enabled (`--dangerously-skip-permissions`)
 *   - Parallel subagents disabled (`--disallowedTools "Agent,Task,TeamCreate,SendMessage"`
 *     + `CLAUDE_CODE_DISABLE_SUBAGENTS=1` + `CLAUDE_CODE_DISABLE_BACKGROUND_TASKS=1`)
 *   - `--bare` mode enabled so untrusted target repositories cannot inject instructions
 *     via `CLAUDE.md`, local hooks, or plugin configs, and host keychains are never read.
 */

import { execFile } from "node:child_process";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseLooseJson } from "./json.js";
import type { ExecFn, Explorer, ExploreTask } from "./orbcode.js";

export interface ClaudeConfig {
  /** Absolute path to the `claude` binary or `cli.js` entrypoint. */
  readonly bin: string;
  /** Inference gateway base URL (e.g. `https://api2.matterai.so/v1` or `https://api2.matterai.so`). */
  readonly baseUrl: string;
  /** API key for the inference gateway. */
  readonly apiKey: string;
  /** Per-run writable directory for session transcripts and config state. */
  readonly scratchDir?: string | null;
  /** Per-invocation timeout in milliseconds. */
  readonly timeoutMs: number;
}

interface ClaudeEnvelope {
  readonly type?: string;
  readonly subtype?: string;
  readonly is_error?: boolean;
  readonly result?: string;
  readonly session_id?: string;
  readonly usage?: {
    readonly input_tokens?: number;
    readonly output_tokens?: number;
  };
  readonly modelUsage?: Record<
    string,
    {
      readonly inputTokens?: number;
      readonly outputTokens?: number;
      readonly canonicalModel?: string;
    }
  >;
}

/**
 * Strip a trailing `/v1` (and trailing slashes) from an OpenAI-style base URL so
 * Claude Code's Anthropic client (`${ANTHROPIC_BASE_URL}/v1/messages`) hits
 * `/v1/messages` instead of `/v1/v1/messages`.
 */
export function normalizeAnthropicBaseUrl(baseUrl: string): string {
  return baseUrl.trim().replace(/\/+$/, "").replace(/\/v1$/i, "");
}

/**
 * Spawn `claude` directly when it is a native binary, or via `process.execPath`
 * when it is a `.js`/`.mjs`/`.cjs` script.
 */
export const realClaudeExec: ExecFn = (bin, args, opts) =>
  new Promise((resolve) => {
    const isJsScript = /\.(?:c|m)?js$/i.test(bin);
    const file = isJsScript ? process.execPath : bin;
    const finalArgs = isJsScript ? [bin, ...args] : [...args];
    execFile(
      file,
      finalArgs,
      { cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code =
          error && typeof (error as { code?: unknown }).code === "number"
            ? (error as { code: number }).code
            : error
              ? null
              : 0;
        resolve({ stdout: String(stdout), stderr: String(stderr), code });
      },
    );
  });

/**
 * Extract the JSON result envelope from Claude Code stdout, ignoring any leading
 * diagnostic lines (such as `[claude-code:unrecognized_model] ...`).
 */
function parseClaudeEnvelope(stdout: string): ClaudeEnvelope | null {
  const lines = stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("{") && line.endsWith("}"));

  for (let i = lines.length - 1; i >= 0; i--) {
    const candidate = parseLooseJson(lines[i]!) as ClaudeEnvelope | null;
    if (
      candidate !== null &&
      typeof candidate === "object" &&
      (candidate.type === "result" || typeof candidate.result === "string" || candidate.is_error === true)
    ) {
      return candidate;
    }
  }

  const fallback = parseLooseJson(stdout) as ClaudeEnvelope | null;
  if (
    fallback !== null &&
    typeof fallback === "object" &&
    (fallback.type === "result" || typeof fallback.result === "string" || fallback.is_error === true)
  ) {
    return fallback;
  }
  return null;
}

/**
 * Build an `Explorer` backed by Claude Code (`claude -p`) with Base URL, Model,
 * and API Key overrides, `--dangerously-skip-permissions`, and parallel subagents disabled.
 */
export function createClaudeExplorer(
  config: ClaudeConfig,
  repoDir: string,
  emit: (level: "info" | "warn", stage: string, message: string) => void,
  onUsage: (tokens: number) => void = () => {},
  exec: ExecFn = realClaudeExec,
): Explorer {
  const cfgDir =
    config.scratchDir !== undefined && config.scratchDir !== null && config.scratchDir.length > 0
      ? config.scratchDir
      : mkdtempSync(join(tmpdir(), "hunter-claude-"));

  const anthropicBaseUrl = normalizeAnthropicBaseUrl(config.baseUrl);
  let counter = 0;
  let sharedSessionId: string | null = null;

  return async <T>(task: ExploreTask): Promise<T | null> => {
    const callNum = ++counter;
    const prompt =
      `${task.system}\n\n${task.task}\n\n` +
      "Do NOT spawn subagents or parallel agents; execute all reads and searches sequentially in this session. " +
      "Produce ONLY the single JSON object the instructions ask for — no prose, no markdown fences.";

    const resume = !task.fresh && sharedSessionId !== null ? ["--resume", sharedSessionId] : [];
    const args = [
      "-p",
      prompt,
      "--bare",
      "--model",
      task.model,
      "--output-format",
      "json",
      "--dangerously-skip-permissions",
      "--disallowedTools",
      "Agent,Task,TeamCreate,SendMessage",
      ...resume,
    ];

    // Strip NODE_OPTIONS from the child environment so any Node process or native
    // binary invoked by Claude Code does not inherit the parent's `--permission` flags.
    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      NODE_OPTIONS: "",
      CLAUDE_CONFIG_DIR: cfgDir,
      ANTHROPIC_BASE_URL: anthropicBaseUrl,
      ANTHROPIC_API_KEY: config.apiKey,
      ANTHROPIC_AUTH_TOKEN: config.apiKey,
      ANTHROPIC_MODEL: task.model,
      ANTHROPIC_DEFAULT_SONNET_MODEL: task.model,
      ANTHROPIC_DEFAULT_OPUS_MODEL: task.model,
      ANTHROPIC_DEFAULT_HAIKU_MODEL: task.model,
      ANTHROPIC_SMALL_FAST_MODEL: task.model,
      CLAUDE_CODE_SUBAGENT_MODEL: task.model,
      CLAUDE_CODE_DISABLE_SUBAGENTS: "1",
      CLAUDE_CODE_DISABLE_BACKGROUND_TASKS: "1",
      CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: "1",
    };

    const startMs = Date.now();
    console.log(
      `[claude #${callNum}] starting stage=${task.stage} model=${task.model} baseUrl=${anthropicBaseUrl} resume=${resume[1] ?? "none"} cwd=${repoDir}`,
    );

    let raw: Awaited<ReturnType<ExecFn>>;
    try {
      raw = await exec(config.bin, args, {
        cwd: repoDir,
        env: childEnv,
        timeoutMs: config.timeoutMs,
      });
    } catch (error) {
      console.warn(`[claude #${callNum}] exec threw after ${Date.now() - startMs}ms:`, error);
      emit("warn", task.stage, `claude run failed: ${msg(error)}`);
      return null;
    }

    const elapsedMs = Date.now() - startMs;
    const envelope = parseClaudeEnvelope(raw.stdout);
    if (envelope === null) {
      const detail = (raw.stderr || raw.stdout).trim().slice(0, 300);
      console.warn(
        `[claude #${callNum}] non-JSON output after ${elapsedMs}ms (exit=${raw.code}): ${detail}`,
      );
      emit("warn", task.stage, "claude did not return a JSON envelope");
      return null;
    }

    const tokens = (envelope.usage?.input_tokens ?? 0) + (envelope.usage?.output_tokens ?? 0);
    console.log(
      `[claude #${callNum}] finished stage=${task.stage} is_error=${Boolean(envelope.is_error)} model=${task.model} tokens=${tokens} session=${envelope.session_id ?? "none"} (${elapsedMs}ms)`,
    );
    if (tokens > 0) {
      onUsage(tokens);
    }

    // Verify modelUsage if reported so we never silently accept a wrong fallback model
    if (envelope.modelUsage && typeof envelope.modelUsage === "object") {
      const usedModels = Object.keys(envelope.modelUsage);
      if (usedModels.length > 0 && !usedModels.includes(task.model)) {
        emit(
          "warn",
          task.stage,
          `claude ran "${usedModels[0]}", not "${task.model}"; discarding`,
        );
        return null;
      }
    }

    if (envelope.is_error === true || typeof envelope.result !== "string") {
      emit(
        "warn",
        task.stage,
        `claude reported an error: ${typeof envelope.result === "string" ? envelope.result.slice(0, 200) : "empty result"}`,
      );
      return null;
    }

    if (!task.fresh && typeof envelope.session_id === "string" && envelope.session_id.length > 0) {
      sharedSessionId = envelope.session_id;
    }

    const parsed = parseLooseJson(envelope.result);
    if (parsed === null) {
      emit("warn", task.stage, "claude returned no usable JSON result");
      return null;
    }
    return parsed as T;
  };
}

function msg(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
