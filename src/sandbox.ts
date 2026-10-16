/**
 * Running a hunt in an isolated child process.
 *
 * Each run is its own process, started with:
 *   - an empty environment, so it cannot read the shared secret, the Redis URL,
 *     or the matterai.so key the parent holds in its own process environment —
 *     the one run's worth of model credentials it needs crosses over IPC instead
 *     (see `RunInput` in `types.ts`), scoped to this run rather than ambient;
 *   - Node's permission model, so it can read only its own compiled code and can
 *     neither write files nor spawn further processes;
 *   - a heap cap, so one run cannot take the service down with it.
 *
 * The parent keeps every connection (Redis, the database) and relays what the
 * child reports. The container is the outer boundary; the child process is the
 * inner one, per run. See `scope.ts` for what this isolation does and does not
 * cover — notably, not the network.
 */

import { fork, type ForkOptions } from "node:child_process";
import { realpathSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { executeRun, type ToolBroker } from "./pipeline.js";
import type { ModelConfig } from "./models/index.js";
import type { ModelClient } from "./models/types.js";
import type { ChildMessage, ParentMessage, RunInput } from "./types.js";

/** Heap limit for one run, in megabytes. */
const RUN_HEAP_MB = 512;

/** A running hunt: wait for it to exit, send it a message, or kill it. */
export interface RunHandle {
  readonly exited: Promise<void>;
  kill(): void;
  /** Send a message down to the run (the answer to a brokered tool request). */
  send(message: ParentMessage): void;
}

/** Starts a hunt and relays its messages. */
export type Spawner = (
  input: RunInput,
  onMessage: (message: ChildMessage) => void,
) => RunHandle;

/**
 * The environment and flags every sandboxed child is started with.
 *
 * `scratchDir` is the one directory the child may write — the orbcode runtime's
 * config and result files. `orbcodeRoot`, when set, names the orbcode install
 * directory and marks this as an orbcode run: the built-in loop passes null and
 * keeps the no-spawn, no-addon, no-extra-read guarantee.
 *
 * Node propagates the permission model to child processes through `NODE_OPTIONS`,
 * so a grandchild — the orbcode harness the child spawns — inherits `--permission`
 * and this exact allow-list. orbcode therefore needs three further grants to run
 * at all: read on its own install tree (to load its code and node_modules),
 * `--allow-addons` (its native dependencies, e.g. the canvas binding pdfjs pulls
 * in, load through N-API, which the permission model blocks by default), and
 * `--allow-child-process` (it shells out to `git` and `rg`). Its own state —
 * sessions, usage, settings — is redirected into `scratchDir` via
 * `MATTERAI_CONFIG_DIR` in orbcode.ts, so no write grant beyond scratch is needed.
 */
export function sandboxOptions(
  codeDir: string,
  repoDir?: string | null,
  proxyUrl?: string | null,
  scratchDir?: string | null,
  orbcodeRoot?: string | null,
): Pick<ForkOptions, "env" | "execArgv"> {
  const reads = [`--allow-fs-read=${codeDir}/*`];
  if (repoDir !== undefined && repoDir !== null) {
    // Read-only, and read is the only grant: the child still cannot write to the
    // checkout or spawn anything from it. It reads source as text; it never runs it.
    reads.push(`--allow-fs-read=${repoDir}/*`);
  }
  const writes: string[] = [];
  if (scratchDir !== undefined && scratchDir !== null) {
    reads.push(`--allow-fs-read=${scratchDir}/*`);
    writes.push(`--allow-fs-write=${scratchDir}`);
  }
  const orbcode = orbcodeRoot !== undefined && orbcodeRoot !== null && orbcodeRoot.length > 0;
  if (orbcode) {
    // The orbcode harness runs as a grandchild under this same inherited
    // allow-list; it must be able to read its own code and dependencies.
    reads.push(`--allow-fs-read=${orbcodeRoot}/*`);
  }

  const env: Record<string, string> = {};
  if (proxyUrl !== undefined && proxyUrl !== null) {
    // Route all HTTP/HTTPS traffic through the scoped egress proxy.
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.http_proxy = proxyUrl;
    env.https_proxy = proxyUrl;
  }
  // PATH carries no secret, and the harness process the orbcode runtime spawns
  // needs it to find `git` and `rg`. Everything else stays out of the child.
  if (process.env.PATH !== undefined && process.env.PATH.length > 0) {
    env.PATH = process.env.PATH;
  }

  const execArgv = ["--permission", ...reads, ...writes];
  if (orbcode) {
    // Only the orbcode runtime spawns a harness and loads native addons; the
    // built-in loop gets neither, so its no-spawn guarantee is unchanged.
    execArgv.push("--allow-child-process", "--allow-addons");
  }
  execArgv.push(`--max-old-space-size=${RUN_HEAP_MB}`);
  return { env, execArgv };
}

/**
 * Resolve a path the permission model will check, falling back to the given path
 * when it does not exist. A missing orbcode install must not crash the spawn — the
 * child fails that run closed with `orbcode_unavailable` instead.
 */
function resolveExisting(path: string): string {
  try {
    return realpathSync(path);
  } catch {
    return path;
  }
}

/** The real spawner: one sandboxed child process per run. */
export function forkSpawner(): Spawner {
  // Real path: the permission model checks the resolved path, so a symlinked
  // install would otherwise be refused.
  const childPath = realpathSync(fileURLToPath(new URL("./run-child.js", import.meta.url)));

  return (input, onMessage) => {
    const repoDir = input.repoDir === null ? undefined : realpathSync(input.repoDir);
    const scratchDir = input.scratchDir === null ? undefined : realpathSync(input.scratchDir);
    // The orbcode harness is spawned from the sandboxed child and inherits its
    // permission model, so its install tree (two levels up from `bin/orbcode.js`)
    // must be granted read. Only an orbcode run resolves one; anything else leaves
    // it undefined and gets no spawn, addon, or extra-read grant.
    const claudeBin = input.credentials.claudeBin ?? "";
    const orbcodeRoot =
      input.credentials.agentRuntime === "orbcode" && input.credentials.orbcodeBin.length > 0
        ? resolveExisting(dirname(dirname(input.credentials.orbcodeBin)))
        : input.credentials.agentRuntime === "claude" && claudeBin.length > 0
          ? resolveExisting(dirname(dirname(claudeBin)))
          : undefined;
    const child = fork(childPath, [], {
      ...sandboxOptions(dirname(childPath), repoDir, input.proxyUrl, scratchDir, orbcodeRoot),
      stdio: ["ignore", "inherit", "inherit", "ipc"],
    });

    child.on("message", (message) => onMessage(message as ChildMessage));
    const exited = new Promise<void>((resolve) => {
      child.once("exit", () => resolve());
      child.once("error", () => resolve());
    });
    // Send the realpath so the child reads the same path the allowance names.
    child.send({ ...input, repoDir: repoDir ?? null, scratchDir: scratchDir ?? null });

    return {
      exited,
      kill: () => void child.kill("SIGKILL"),
      send: (message) => {
        try {
          child.send(message);
        } catch {
          // The child is gone; a brokered reply with nowhere to land is harmless.
        }
      },
    };
  };
}

/**
 * Runs the same pipeline code in this process, without forking.
 *
 * For tests only: `makeClient` and `baseFetch` let a test run the real stage
 * logic against a scripted model and a fake network instead of matterai.so and a
 * live target. Production always uses `forkSpawner`, which has no such override.
 */
export function inProcessSpawner(
  makeClient?: (config: ModelConfig) => ModelClient,
  baseFetch?: typeof fetch,
  broker?: ToolBroker,
): Spawner {
  return (input, onMessage) => {
    let killed = false;
    const exited = executeRun(
      input,
      (message) => {
        if (!killed) {
          onMessage(message);
        }
      },
      { makeClient, baseFetch, broker },
    ).catch(() => undefined);
    // In-process the broker is called directly, so there is nothing to send back.
    return { exited, kill: () => void (killed = true), send: () => {} };
  };
}
