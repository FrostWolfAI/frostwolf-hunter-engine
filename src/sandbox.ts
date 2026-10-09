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

/** The environment and flags every sandboxed child is started with. */
export function sandboxOptions(
  codeDir: string,
  repoDir?: string | null,
  proxyUrl?: string | null,
): Pick<ForkOptions, "env" | "execArgv"> {
  const reads = [`--allow-fs-read=${codeDir}/*`];
  if (repoDir !== undefined && repoDir !== null) {
    // Read-only, and read is the only grant: the child still cannot write to the
    // checkout or spawn anything from it. It reads source as text; it never runs it.
    reads.push(`--allow-fs-read=${repoDir}/*`);
  }

  const env: Record<string, string> = {};
  if (proxyUrl !== undefined && proxyUrl !== null) {
    // Route all HTTP/HTTPS traffic through the scoped egress proxy.
    env.HTTP_PROXY = proxyUrl;
    env.HTTPS_PROXY = proxyUrl;
    env.http_proxy = proxyUrl;
    env.https_proxy = proxyUrl;
  }

  return {
    env,
    execArgv: ["--permission", ...reads, `--max-old-space-size=${RUN_HEAP_MB}`],
  };
}

/** The real spawner: one sandboxed child process per run. */
export function forkSpawner(): Spawner {
  // Real path: the permission model checks the resolved path, so a symlinked
  // install would otherwise be refused.
  const childPath = realpathSync(fileURLToPath(new URL("./run-child.js", import.meta.url)));

  return (input, onMessage) => {
    const repoDir = input.repoDir === null ? undefined : realpathSync(input.repoDir);
    const child = fork(childPath, [], {
      ...sandboxOptions(dirname(childPath), repoDir, input.proxyUrl),
      stdio: ["ignore", "inherit", "inherit", "ipc"],
    });

    child.on("message", (message) => onMessage(message as ChildMessage));
    const exited = new Promise<void>((resolve) => {
      child.once("exit", () => resolve());
      child.once("error", () => resolve());
    });
    // Send the realpath so the child reads the same path the allowance names.
    child.send({ ...input, repoDir: repoDir ?? null });

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
