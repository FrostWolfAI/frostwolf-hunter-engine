/**
 * Hunter entry point.
 *
 * One always-on HTTP service. A hunt is started by a direct API call
 * (`POST /v1/hunter/hunts/:id/start`) and runs in this process, each in its own
 * sandboxed child; there is no queue and no Redis. It reaches D1 through the
 * gateway worker with one shared secret, calls matterai.so (or, once it ships,
 * Clef) for model calls — the API key handed to each run's child over IPC, never
 * its environment — and streams the live log from memory.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, realpathSync } from "node:fs";
import { join, resolve } from "node:path";
import { loadConfig } from "./config.js";
import { D1Client } from "./d1.js";
import { serve } from "./http.js";
import { createMemoryLive } from "./live.js";
import { cloneRepo } from "./repo.js";
import { processRun } from "./runner.js";
import { createHandler } from "./routes.js";
import { forkSpawner } from "./sandbox.js";
import { createCommandRunner } from "./sandbox-exec.js";
import { createStore } from "./store.js";
import { createWebSearch } from "./web-search.js";
import type { RunCredentials, RunJob } from "./types.js";

/**
 * Load `.env` from the current working directory if present, without overriding
 * environment variables already set by the process manager, Docker, or shell.
 */
function loadDotEnvIfPresent(): void {
  const envPath = resolve(process.cwd(), ".env");
  if (!existsSync(envPath)) {
    return;
  }
  try {
    const content = readFileSync(envPath, "utf8");
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.length === 0 || line.startsWith("#")) {
        continue;
      }
      const eq = line.indexOf("=");
      if (eq <= 0) {
        continue;
      }
      const key = line.slice(0, eq).trim();
      let value = line.slice(eq + 1).trim();
      if (
        (value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))
      ) {
        value = value.slice(1, -1);
      } else {
        const hashIdx = value.indexOf(" #");
        if (hashIdx !== -1) {
          value = value.slice(0, hashIdx).trim();
        }
      }
      if (process.env[key] === undefined) {
        process.env[key] = value;
      }
    }
  } catch {
    // Ignore unreadable .env and fall back to process.env
  }
}

/**
 * Auto-discover the orbcode CLI entrypoint (`bin/orbcode.js`) on any Linux/macOS VM
 * when `ORBCODE_BIN` is unset or points to a path from another machine.
 */
function ensurePortableOrbcodeBin(): void {
  const current = process.env.ORBCODE_BIN?.trim() ?? "";
  if (current.length > 0 && existsSync(current)) {
    return;
  }

  const candidates: string[] = [
    "/usr/local/lib/node_modules/@matterailab/orbcode/bin/orbcode.js",
    "/usr/lib/node_modules/@matterailab/orbcode/bin/orbcode.js",
    "/opt/homebrew/lib/node_modules/@matterailab/orbcode/bin/orbcode.js",
  ];

  try {
    const whichOut = execFileSync("which", ["orbcode"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (whichOut.length > 0 && existsSync(whichOut)) {
      candidates.unshift(realpathSync(whichOut));
    }
  } catch {
    // `orbcode` not on PATH
  }

  try {
    const npmGlobalRoot = execFileSync("npm", ["root", "-g"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (npmGlobalRoot.length > 0) {
      candidates.push(join(npmGlobalRoot, "@matterailab", "orbcode", "bin", "orbcode.js"));
    }
  } catch {
    // npm root -g unavailable
  }

  for (const candidate of candidates) {
    if (candidate.length > 0 && existsSync(candidate)) {
      process.env.ORBCODE_BIN = candidate;
      return;
    }
  }
}

function toCredentials(config: ReturnType<typeof loadConfig>): RunCredentials {
  return {
    aiProvider: config.aiProvider,
    aiBaseUrl: config.aiBaseUrl,
    aiApiKey: config.aiApiKey,
    attackerModel: config.attackerModel,
    verifierModel: config.verifierModel,
    judgeModel: config.judgeModel,
    verifyN: config.verifyN,
    costPer1kTokensUsd: config.costPer1kTokensUsd,
    agentRuntime: config.agentRuntime,
    orbcodeBin: config.orbcodeBin,
    claudeBin: config.claudeBin,
    judgeProvider: config.judgeProvider,
    judgeBaseUrl: config.judgeBaseUrl,
  };
}

async function main(): Promise<void> {
  loadDotEnvIfPresent();
  ensurePortableOrbcodeBin();
  if (!process.env.ATTACKER_MODEL) {
    process.env.ATTACKER_MODEL = "frost-abliterated-cyber-max-1";
  }
  if (!process.env.VERIFIER_MODEL) {
    process.env.VERIFIER_MODEL = "frost-abliterated-cyber-max-1";
  }
  if (!process.env.JUDGE_MODEL) {
    process.env.JUDGE_MODEL = "fastino/gliner2.5-decide-free";
  }

  const config = loadConfig();
  if (config.secret.length === 0) {
    throw new Error("HUNTER_SECRET is required.");
  }
  if (config.aiApiKey.length === 0) {
    console.warn(
      "MATTERAI_API_KEY is not set — every run will fail closed at intake until it is configured.",
    );
  }
  if (config.agentRuntime === "orbcode" && config.orbcodeBin.length === 0) {
    console.warn(
      `AGENT_RUNTIME=orbcode but the orbcode launcher was not found (ORBCODE_BIN=${
        process.env.ORBCODE_BIN ?? "<unset>"
      }). Set ORBCODE_BIN to an existing bin/orbcode.js, or install @matterailab/orbcode. Every run will fail closed with orbcode_unavailable until it resolves.`,
    );
  }
  if (config.agentRuntime === "claude" && config.claudeBin.length === 0) {
    console.warn(
      `AGENT_RUNTIME=claude but the claude CLI was not found (CLAUDE_BIN=${
        process.env.CLAUDE_BIN ?? "<unset>"
      }). Set CLAUDE_BIN to an existing claude binary, or install @anthropic-ai/claude-code. Every run will fail closed with claude_unavailable until it resolves.`,
    );
  }

  const env = { DB: new D1Client(config) };
  const store = createStore(env);
  const live = createMemoryLive();
  const spawn = forkSpawner();
  const credentials = toCredentials(config);

  const prepareRepo = (job: RunJob): Promise<Awaited<ReturnType<typeof cloneRepo>> | null> =>
    job.repoUrl === null ? Promise.resolve(null) : cloneRepo(job.repoUrl);

  const webSearch = createWebSearch({
    apiKey: config.fireworksApiKey,
    baseUrl: config.fireworksBaseUrl,
    maxResults: 5,
  });
  const capabilities = {
    bash: true,
    webSearch: config.fireworksApiKey.trim().length > 0,
  };
  const makeCommandRunner = (repoDir: string) =>
    createCommandRunner(
      {
        image: config.sandboxImage,
        ociRuntime: config.sandboxOciRuntime,
        network: "none",
        cpus: "2",
        memory: "2g",
        pidsLimit: 512,
        commandTimeoutMs: 120_000,
      },
      repoDir,
    );

  // A hunt is started by a direct API call and runs in this process — no queue.
  // Fire-and-forget: the HTTP response returns 202 immediately and the client
  // follows the live log; a crash surfaces in the run's own events and status.
  const execute = (runId: string): void => {
    console.log(`[hunter] kicking off run ${runId}`);
    void processRun(runId, {
      store,
      live,
      spawn,
      credentials,
      timeoutMs: config.runTimeoutMs,
      prepareRepo,
      capabilities,
      makeCommandRunner,
      webSearch,
    })
      .then((res) => {
        console.log(
          `[hunter] run ${runId} completed: status=${res.status}${res.reason ? ` reason=${res.reason}` : ""} cost=$${res.cost.toFixed(4)} findings=${res.findings}`,
        );
      })
      .catch((error: unknown) => console.error(`[hunter] run ${runId} failed:`, error));
  };

  const server = serve(
    createHandler({
      secret: config.secret,
      env,
      execute,
      liveStream: (runId) => live.stream(runId),
    }),
  );
  server.listen(config.port, () => {
    console.log(`hunter listening on :${config.port}`);
    console.log(
      `[hunter] config: worker=${config.workerUrl} runtime=${config.agentRuntime} orbcodeBin=${config.orbcodeBin || "<none>"} claudeBin=${config.claudeBin || "<none>"} attacker=${config.attackerModel} verifier=${config.verifierModel} judge=${config.judgeProvider}(${config.judgeModel}) verifyN=${config.verifyN}`,
    );
  });

  const shutdown = (): void => {
    server.close();
    process.exit(0);
  };
  process.on("SIGTERM", shutdown);
  process.on("SIGINT", shutdown);
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
