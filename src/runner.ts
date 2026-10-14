/**
 * Processing one run.
 *
 * Starts the run's sandboxed child and relays what it reports: log lines go to
 * Redis for anyone watching and, in batches, to D1 as the durable copy; every
 * hypothesis, every JEV verdict, and every finding go to D1 as they arrive, so
 * the decision trail is persisted as the run makes it, not reconstructed after.
 * The parent owns every connection; the child owns none. A run that is stopped
 * from the console, or that exceeds its budget, has its child killed.
 */

import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderExec, type CommandRunner } from "./sandbox-exec.js";
import { startEgressProxy, type EgressProxy } from "./egress-proxy.js";
import { scopeHosts } from "./scope.js";
import type { Live } from "./live.js";
import type { PreparedRepo } from "./repo.js";
import type { Spawner } from "./sandbox.js";
import type { Store } from "./store.js";
import type {
  ChildMessage,
  RunCapabilities,
  RunCredentials,
  RunEvent,
  RunJob,
  RunStatus,
} from "./types.js";
import type { WebSearch } from "./web-search.js";

/** How often buffered log lines are flushed to the database, in milliseconds. */
const FLUSH_MS = 1_000;

export interface RunnerDeps {
  readonly store: Store;
  readonly live: Live;
  readonly spawn: Spawner;
  readonly credentials: RunCredentials;
  readonly timeoutMs: number;
  /**
   * Clone the job's repository (parent side), or return null when it has none.
   * Injected so a test can hand the child a fixture directory instead of cloning.
   */
  readonly prepareRepo: (job: RunJob) => Promise<PreparedRepo | null>;
  /** Which brokered tools this deployment can service at all. */
  readonly capabilities: RunCapabilities;
  /** Build the per-run `bash` runner bound to the checkout (parent side). */
  readonly makeCommandRunner: (repoDir: string) => CommandRunner;
  /** The web-search backend (parent side). */
  readonly webSearch: WebSearch;
}

export interface RunResult {
  readonly status: RunStatus;
  readonly reason?: string;
  readonly cost: number;
  readonly findings: number;
}

export async function processRun(runId: string, deps: RunnerDeps): Promise<RunResult> {
  const { store, live } = deps;
  const log = (msg: string): void => console.log(`[run ${runId}] ${msg}`);

  if (await store.isStopped(runId)) {
    log("already stopped before start");
    return { status: "stopped", cost: 0, findings: 0 };
  }

  const job = await store.getJob(runId);
  if (job === null) {
    log("job not found or connection revoked; failing at intake");
    await store.setStatus(runId, "failed", { stage: "intake" });
    await live.end(runId, "failed");
    return { status: "failed", reason: "unknown run or revoked connection", cost: 0, findings: 0 };
  }

  log(`loaded job: hunt=${job.hunt_id} tenant=${job.tenant_id} repo=${job.repoUrl ?? "<none>"} depth=${job.depth}`);
  await store.setStatus(runId, "running");

  // Clone the target repository before the child is spawned — only the parent can
  // reach the network and run `git`. A clone failure fails the run closed; the child
  // never starts without the source it is meant to analyse.
  let repo: PreparedRepo | null = null;
  try {
    if (job.repoUrl !== null) {
      log(`cloning repo ${job.repoUrl} ...`);
    }
    repo = await deps.prepareRepo(job);
    if (repo !== null) {
      log(`repo cloned to ${repo.dir}`);
    }
  } catch (error) {
    const reason = error instanceof Error ? error.message : "repository could not be prepared";
    log(`clone failed: ${reason}`);
    await store.appendEvents(runId, [
      { level: "error", stage: "intake", message: `clone failed: ${reason}`, ts: new Date().toISOString() },
    ]).catch(() => undefined);
    await store.setStatus(runId, "failed", { stage: "intake" });
    await live.end(runId, "failed");
    return { status: "failed", reason: "repo_unavailable", cost: 0, findings: 0 };
  }

  // `bash` is only offered when a container runtime is configured AND a checkout
  // exists; the runner, in the parent, is what actually executes it.
  const commandRunner =
    repo !== null && deps.capabilities.bash ? deps.makeCommandRunner(repo.dir) : null;
  const capabilities: RunCapabilities = {
    bash: commandRunner !== null,
    webSearch: deps.capabilities.webSearch,
  };

  // Start the scoped egress proxy. All child network traffic routes through it,
  // and it refuses any host outside the declared scope — the OS-level boundary.
  let proxy: EgressProxy | null = null;
  try {
    proxy = await startEgressProxy({
      hosts: scopeHosts(job),
      onRequest: (url, allowed) => {
        if (!allowed) {
          buffer.push({
            level: "warn",
            stage: "egress",
            message: `blocked out-of-scope request: ${url}`,
            ts: new Date().toISOString(),
          });
        }
      },
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : "egress proxy failed to start";
    await store.appendEvents(runId, [
      { level: "error", stage: "intake", message: `egress proxy failed: ${reason}`, ts: new Date().toISOString() },
    ]).catch(() => undefined);
    await store.setStatus(runId, "failed", { stage: "intake" });
    await live.end(runId, "failed");
    return { status: "failed", reason: "egress_proxy_unavailable", cost: 0, findings: 0 };
  }

  let cost = 0;
  let findings = 0;
  let stopped = false;
  let timedOut = false;
  let outcome: { ok: boolean; reason?: string } | null = null;
  let buffer: RunEvent[] = [];

  const flush = async (): Promise<void> => {
    if (buffer.length === 0) {
      return;
    }
    const batch = buffer;
    buffer = [];
    try {
      await store.appendEvents(runId, batch);
    } catch {
      // Keep the lines for the next flush rather than losing them.
      buffer = [...batch, ...buffer];
    }
  };
  const flusher = setInterval(() => void flush(), FLUSH_MS);

  // Messages are handled one at a time, in the order the child sent them.
  let chain: Promise<void> = Promise.resolve();
  const handle = async (message: ChildMessage): Promise<void> => {
    switch (message.type) {
      case "stage":
        log(`stage -> ${message.name}`);
        await store.setStatus(runId, "running", { stage: message.name });
        if (!stopped && (await store.isStopped(runId))) {
          log("stop requested from console; killing child");
          stopped = true;
          run.kill();
        }
        break;
      case "event":
        log(`[${message.event.level}] ${message.event.stage}: ${message.event.message}`);
        buffer.push(message.event);
        await live.publish(runId, message.event);
        break;
      case "hypothesis":
        log(`hypothesis ${message.hypothesis.code} (${message.hypothesis.predicted_class}): ${message.hypothesis.rationale}`);
        await store.addHypothesis(runId, message.hypothesis);
        break;
      case "hypothesis_status":
        log(`hypothesis ${message.code} status -> ${message.status}`);
        await store.setHypothesisStatus(runId, message.code, message.status);
        break;
      case "verdict":
        log(`verdict ${message.gate}${message.hypothesis_code ? ` (${message.hypothesis_code})` : ""}: ${message.verdict.verdict} (confidence=${message.verdict.confidence})`);
        await store.addVerdict(runId, message.gate, message.hypothesis_code, message.verdict);
        break;
      case "finding":
        findings += 1;
        log(`finding #${findings} [${message.finding.severity}] ${message.finding.title} (${message.finding.location})`);
        await store.addFinding(runId, message.finding);
        break;
      case "spend":
        cost += message.usd;
        break;
      case "tool_request": {
        log(`tool_request: ${message.tool} ${JSON.stringify(message.args)}`);
        // The child cannot run these itself; the parent executes and replies.
        let result: string;
        if (message.tool === "bash") {
          const cmd = typeof message.args.cmd === "string" ? message.args.cmd : "";
          result =
            commandRunner === null
              ? "bash is unavailable for this run."
              : renderExec(await commandRunner.exec(cmd));
        } else {
          const query = typeof message.args.query === "string" ? message.args.query : "";
          result = await deps.webSearch.search(query);
        }
        run.send({ type: "tool_response", id: message.id, result });
        break;
      }
      case "done":
        log(`child reported done: ok=${message.ok}${message.reason ? ` reason=${message.reason}` : ""}`);
        outcome = {
          ok: message.ok,
          ...(message.reason === undefined ? {} : { reason: message.reason }),
        };
        break;
    }
  };

  // The one writable directory the child gets: the orbcode runtime writes its
  // model config and reads back result files here. Per run, deleted below.
  const scratchDir = await mkdtemp(join(tmpdir(), "hunter-scratch-"));
  log(`spawning sandboxed child (scratchDir=${scratchDir}, proxy=${proxy.url})`);

  const run = deps.spawn(
    {
      job,
      credentials: deps.credentials,
      capabilities,
      repoDir: repo?.dir ?? null,
      scratchDir,
      proxyUrl: proxy.url,
    },
    (message) => {
      chain = chain.then(() => handle(message)).catch((err) => {
        console.error(`[run ${runId}] error handling child message (${message.type}):`, err);
      });
    },
  );

  const timer = setTimeout(() => {
    timedOut = true;
    run.kill();
  }, deps.timeoutMs);

  await run.exited;
  clearTimeout(timer);
  await chain;
  clearInterval(flusher);
  await flush();
  // Tear down the sandbox container, close the egress proxy, then delete the
  // disposable checkout.
  await commandRunner?.dispose().catch(() => undefined);
  await proxy?.close().catch(() => undefined);
  await repo?.cleanup().catch(() => undefined);
  await rm(scratchDir, { recursive: true, force: true }).catch(() => undefined);

  const result = finalise(outcome, { stopped, timedOut });
  if (result.status === "failed" && result.reason !== undefined) {
    // The reason a run failed is part of the run's record, not just a return
    // value: the console replays events, and a failure with no visible cause is
    // indistinguishable from a crash of the service itself.
    await store
      .appendEvents(runId, [
        {
          level: "error",
          stage: "run",
          message: `run failed: ${result.reason}`,
          ts: new Date().toISOString(),
        },
      ])
      .catch(() => undefined);
  }
  await store.setStatus(runId, result.status, { cost_usd: cost });
  await store.meter(runId, { hunts: 1, verifications: findings });
  await live.end(runId, result.status);

  return { ...result, cost, findings };
}

function finalise(
  outcome: { ok: boolean; reason?: string } | null,
  flags: { stopped: boolean; timedOut: boolean },
): { status: RunStatus; reason?: string } {
  if (flags.stopped) {
    return { status: "stopped" };
  }
  if (flags.timedOut) {
    return { status: "failed", reason: "run exceeded its time budget" };
  }
  if (outcome === null) {
    return { status: "failed", reason: "the run exited without finishing" };
  }
  return outcome.ok
    ? { status: "completed" }
    : { status: "failed", reason: outcome.reason ?? "refused" };
}
