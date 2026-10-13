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
    maxRunTokens: config.maxRunTokens,
    agentRuntime: config.agentRuntime,
    orbcodeBin: config.orbcodeBin,
    judgeProvider: config.judgeProvider,
    judgeBaseUrl: config.judgeBaseUrl,
  };
}

async function main(): Promise<void> {
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
    }).catch((error: unknown) => console.error(`run ${runId} failed:`, error));
  };

  const server = serve(
    createHandler({
      secret: config.secret,
      env,
      execute,
      liveStream: (runId) => live.stream(runId),
    }),
  );
  server.listen(config.port, () => console.log(`hunter listening on :${config.port}`));

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
