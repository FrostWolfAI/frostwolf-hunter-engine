/**
 * Hunter entry point.
 *
 * One service: an HTTP API for the gateway worker, a run queue on a native Redis
 * stream, and a worker pool that runs each hunt in its own sandboxed child
 * process. It connects to Redis directly and to D1 through the gateway worker,
 * with one shared secret, and to matterai.so (or, once it ships, Clef) for model
 * calls, with the API key handed to each run's child over IPC rather than through
 * its environment.
 */

import { Redis } from "ioredis";
import { loadConfig } from "./config.js";
import { D1Client } from "./d1.js";
import { serve } from "./http.js";
import { createLive, liveStream } from "./live.js";
import { createQueue, startWorker } from "./queue.js";
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

  const redis = new Redis(config.redisUrl, { maxRetriesPerRequest: null });
  const env = { DB: new D1Client(config) };
  const store = createStore(env);
  const live = createLive(redis);
  const queue = createQueue(config, redis);
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
    bash: config.sandboxRuntime !== "none",
    webSearch: config.fireworksApiKey.trim().length > 0,
  };
  if (!capabilities.bash) {
    console.warn("SANDBOX_RUNTIME is not set — the bash tool is disabled (no host execution).");
  }
  const makeCommandRunner = (repoDir: string) =>
    createCommandRunner(
      {
        runtime: config.sandboxRuntime,
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

  const worker = startWorker(config, redis, (runId) =>
    processRun(runId, {
      store,
      live,
      spawn,
      credentials,
      timeoutMs: config.runTimeoutMs,
      prepareRepo,
      capabilities,
      makeCommandRunner,
      webSearch,
    }),
  );

  const server = serve(
    createHandler({
      secret: config.secret,
      env,
      enqueue: (runId) => queue.add(runId),
      liveStream: (runId) => liveStream(redis, runId),
    }),
  );
  server.listen(config.port, () => console.log(`hunter listening on :${config.port}`));

  const shutdown = async (): Promise<void> => {
    server.close();
    await worker.close();
    await queue.close();
    await redis.quit();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown());
  process.on("SIGINT", () => void shutdown());
}

main().catch((error: unknown) => {
  console.error(error);
  process.exit(1);
});
