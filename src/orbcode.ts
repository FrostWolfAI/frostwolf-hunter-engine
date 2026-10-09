/**
 * The orbcode agent as Hunter's generator runtime.
 *
 * Hunter does not reimplement a coding agent. For the *generator* stages — recon,
 * synthesis, independent re-derivation — it drives the orbcode harness headlessly:
 * a mature agent loop with real read/search/edit/bash tools, pointed at the cloned
 * repository, running whatever model we configure. orbcode explores; it does not
 * decide. Everything that makes Hunter a red-teaming product — the JEV judge layer,
 * the explore→independent-verify split, N/N promotion, cross-repo reasoning, scope
 * enforcement, the control plane — stays here, around orbcode. orbcode is a
 * swappable substrate behind the same `explore` seam the built-in agent implements.
 *
 * Reliability comes from orbcode's structured headless mode:
 *   --json          one JSON envelope on stdout {ok, model, result, usage, …}
 *   --require-model fail loudly instead of silently running a different model
 *   --output-file   the agent writes its final JSON to a file (robust against a
 *                   weak model mangling the chat message); the write is allowed
 *                   even in read-only mode.
 * We assert the envelope's `model` is the one we asked for, so a run can never
 * quietly fall back off the configured endpoint.
 *
 * Isolation: a read-only run (recon/synthesis/verify) omits `--yolo`, so orbcode's
 * edit/command tools are auto-denied — it can only read, search, and write the one
 * result file. `--yolo` (real edits + bash, the live-exploitation layer) is used
 * ONLY inside the per-run container sandbox, never on the host.
 */

import { execFile } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { parseLooseJson } from "./json.js";

/** How a command is run — injected so a test drives a fake instead of spawning. */
export type ExecFn = (
  bin: string,
  args: readonly string[],
  opts: { cwd: string; env: NodeJS.ProcessEnv; timeoutMs: number },
) => Promise<{ stdout: string; stderr: string; code: number | null }>;

/** One generator task for the substrate. */
export interface ExploreTask {
  readonly model: string;
  readonly system: string;
  readonly task: string;
  readonly stage: string;
  /** Hints the built-in agent honours; the orbcode substrate ignores them. */
  readonly maxSteps?: number;
  readonly temperature?: number;
}

/** Produces a structured result for a generator task, or null. */
export type Explorer = <T>(task: ExploreTask) => Promise<T | null>;

/** orbcode's `--json` stdout envelope. */
interface OrbcodeEnvelope {
  readonly ok: boolean;
  readonly model: string;
  readonly result: string;
  readonly usage?: { readonly inputTokens?: number; readonly outputTokens?: number };
  readonly sessionId?: string;
  readonly error?: string | null;
}

export interface OrbcodeConfig {
  /** Path to the orbcode launcher (`bin/orbcode.js`). */
  readonly bin: string;
  /** OpenAI-compatible endpoint every configured model is served from. */
  readonly baseUrl: string;
  /** Key for that endpoint (may be a placeholder when the endpoint needs none). */
  readonly apiKey: string;
  /** Model ids to register as custom models (attacker, verifier). */
  readonly models: readonly string[];
  /** Whether edits/commands are allowed (`--yolo`). Only true inside the sandbox. */
  readonly execute: boolean;
  readonly timeoutMs: number;
}

/** The real spawner: `node <bin> -p <prompt> …` in `repoDir`. */
export const realExec: ExecFn = (bin, args, opts) =>
  new Promise((resolve) => {
    execFile(
      process.execPath,
      [bin, ...args],
      { cwd: opts.cwd, env: opts.env, timeout: opts.timeoutMs, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error && typeof (error as { code?: unknown }).code === "number"
          ? (error as { code: number }).code
          : error ? null : 0;
        resolve({ stdout: String(stdout), stderr: String(stderr), code });
      },
    );
  });

/**
 * Build an explorer that runs tasks through orbcode in a given checkout.
 *
 * A per-run config dir registers each model (deduped) as an `openai-compatible`
 * custom model, so orbcode authenticates against our endpoint rather than the
 * MatterAI gateway and needs no login. `onUsage` feeds orbcode's reported token
 * usage into the run's cost governor; `emit` surfaces a short log line; `exec` is
 * injectable for tests.
 */
export function createOrbcodeExplorer(
  config: OrbcodeConfig,
  repoDir: string,
  emit: (level: "info" | "warn", stage: string, message: string) => void,
  onUsage: (tokens: number) => void = () => {},
  exec: ExecFn = realExec,
): Explorer {
  const cfgDir = mkdtempSync(join(tmpdir(), "hunter-orb-"));
  const uniqueModels = [...new Set(config.models.filter((m) => m.length > 0))];
  writeFileSync(
    join(cfgDir, "settings.json"),
    JSON.stringify({
      model: uniqueModels[0] ?? "model",
      customModels: uniqueModels.map((id) => ({
        id,
        name: id,
        provider: "openai-compatible",
        baseUrl: config.baseUrl,
        apiKey: config.apiKey,
        contextWindow: 128000,
        maxOutputTokens: 8000,
      })),
    }),
  );
  let counter = 0;

  return async <T>(task: ExploreTask): Promise<T | null> => {
    const outputFile = join(cfgDir, `result-${++counter}.json`);
    const prompt =
      `${task.system}\n\n${task.task}\n\n` +
      "Produce ONLY the single JSON object the instructions ask for — no prose, no fences.";
    const args = [
      "-p", prompt,
      "--model", task.model,
      "--json",
      "--require-model",
      "--output-file", outputFile,
      ...(config.execute ? ["--yolo"] : []),
    ];

    let raw: Awaited<ReturnType<ExecFn>>;
    try {
      raw = await exec(config.bin, args, {
        cwd: repoDir,
        env: { ...process.env, MATTERAI_CONFIG_DIR: cfgDir },
        timeoutMs: config.timeoutMs,
      });
    } catch (error) {
      emit("warn", task.stage, `orbcode run failed: ${msg(error)}`);
      return null;
    } finally {
      rmSync(outputFile, { force: true });
    }

    const envelope = parseLooseJson(raw.stdout) as OrbcodeEnvelope | null;
    if (envelope === null || typeof envelope !== "object") {
      emit("warn", task.stage, "orbcode did not return a JSON envelope");
      return null;
    }
    if (typeof envelope.usage === "object" && envelope.usage !== null) {
      onUsage((envelope.usage.inputTokens ?? 0) + (envelope.usage.outputTokens ?? 0));
    }
    // Never trust output from a model other than the one we asked for.
    if (envelope.model !== task.model) {
      emit("warn", task.stage, `orbcode ran "${envelope.model}", not "${task.model}"; discarding`);
      return null;
    }
    if (!envelope.ok) {
      emit("warn", task.stage, `orbcode reported an error: ${envelope.error ?? "unknown"}`);
      return null;
    }

    const parsed = parseLooseJson(envelope.result);
    if (parsed === null) {
      emit("warn", task.stage, "orbcode returned no usable JSON result");
      return null;
    }
    return parsed as T;
  };
}

function msg(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

/** Read a result file orbcode wrote, if present (exposed for tests/tools). */
export function readResultFile(path: string): string | null {
  try {
    return readFileSync(path, "utf8");
  } catch {
    return null;
  }
}
