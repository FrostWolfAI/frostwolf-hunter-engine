/**
 * The local agent: run one hunt on this machine and PUSH every record to prod.
 *
 * This is what the local Docker bundle does — it clones the repo and drives the
 * real pipeline here (orbcode generators + the models you configure), but it
 * persists the connection, hunt, run, live log, verdicts and findings to the
 * production database through the gateway worker's `/internal/d1`, stamped with an
 * org id so prod knows whose data it is. The org id becomes the tenant on every
 * row, which is what the console/dashboard filters on.
 *
 *   FW_ORG_ID=<org> WORKER_URL=https://api.frostwolf.app \
 *     node --env-file=.env scripts/run-and-push.mjs <repoUrl>
 *
 * Env read: FW_ORG_ID (required), WORKER_URL (required — the prod gateway),
 * HUNTER_SECRET (required — the shared secret the worker authenticates with),
 * MATTERAI_BASE_URL, MATTERAI_API_KEY, ATTACKER_MODEL, VERIFIER_MODEL, JUDGE_MODEL,
 * JUDGE_PROVIDER (default skip), AGENT_RUNTIME (default orbcode), ORBCODE_BIN,
 * VERIFY_N, RUN_TIMEOUT_MS, SANDBOX_IMAGE.
 *
 * Prereqs on the prod side: the three D1 migrations applied, the worker's
 * `/internal/d1` deployed, and HUNTER_SECRET matching. Without them the first
 * write fails loudly (e.g. "no such table" or a 401), which is the point — it
 * never silently drops results.
 */
import { D1Client } from "../dist/d1.js";
import { createStore } from "../dist/store.js";
import { createConnection, createHunt, startRun, listFindings } from "../dist/data/db.js";
import { processRun } from "../dist/runner.js";
import { inProcessSpawner } from "../dist/sandbox.js";
import { createModelClient } from "../dist/models/index.js";
import { cloneRepo } from "../dist/repo.js";
import { disabledWebSearch } from "../dist/web-search.js";
import { createCommandRunner } from "../dist/sandbox-exec.js";

const repo = process.argv[2];
const org = process.env.FW_ORG_ID;
const workerUrl = (process.env.WORKER_URL ?? "").replace(/\/$/, "");
const secret = process.env.HUNTER_SECRET ?? "";
const baseUrl = process.env.MATTERAI_BASE_URL;
const attackerModel = process.env.ATTACKER_MODEL;
const verifierModel = process.env.VERIFIER_MODEL ?? attackerModel;

const runtime =
  process.env.AGENT_RUNTIME === "internal" ? "internal"
  : process.env.AGENT_RUNTIME === "claude" ? "claude"
  : process.env.AGENT_RUNTIME === "codex" ? "codex"
  : "orbcode"; // default

const missing = [];
if (!repo) missing.push("<repoUrl> argument");
if (!org) missing.push("FW_ORG_ID");
if (!workerUrl) missing.push("WORKER_URL (the prod gateway)");
if (!secret) missing.push("HUNTER_SECRET");
if (!baseUrl) missing.push("MATTERAI_BASE_URL");
if (!attackerModel) missing.push("ATTACKER_MODEL");
if (runtime === "orbcode" && !process.env.ORBCODE_BIN) missing.push("ORBCODE_BIN (orbcode is the default runtime)");
if (missing.length > 0) {
  console.error("missing required config:\n  - " + missing.join("\n  - "));
  console.error("\nusage: FW_ORG_ID=<org> WORKER_URL=<prod> node --env-file=.env scripts/run-and-push.mjs <repoUrl>");
  process.exit(2);
}

const credentials = {
  aiProvider: process.env.MODEL_PROVIDER === "clef" ? "clef" : "matterai",
  aiBaseUrl: baseUrl,
  aiApiKey: process.env.MATTERAI_API_KEY ?? "",
  attackerModel,
  verifierModel,
  judgeModel: process.env.JUDGE_MODEL ?? attackerModel,
  judgeProvider: process.env.JUDGE_PROVIDER ?? "skip",
  judgeBaseUrl: process.env.JUDGE_BASE_URL ?? "",
  verifyN: Number(process.env.VERIFY_N ?? 1),
  costPer1kTokensUsd: Number(process.env.COST_PER_1K_TOKENS_USD ?? 0),
  maxRunTokens: Number(process.env.MAX_RUN_TOKENS ?? 2_000_000),
  agentRuntime: runtime,
  orbcodeBin: process.env.ORBCODE_BIN ?? "",
};

// The production database, reached through the gateway worker's /internal/d1.
const env = { DB: new D1Client({ workerUrl, secret }) };
const store = createStore(env);

console.log(`org=${org}  worker=${workerUrl}  runtime=${runtime}  judge=${credentials.judgeProvider}`);
console.log(`models: attacker=${attackerModel} verifier=${verifierModel}`);
console.log(`creating hunt for ${repo} under org ${org} …`);

const connection = await createConnection(env, org, { provider: "github", repos: [repo], runtime: {} });
const hunt = await createHunt(env, org, {
  connection_id: connection.id,
  mode: "oneshot",
  scope: { repo },
  depth: "standard",
  policy: {},
});
if (!hunt) {
  console.error("could not create the hunt (connection rejected?)");
  process.exit(1);
}
const run = await startRun(env, org, hunt.id);
if (!run) {
  console.error("could not start a run for the hunt");
  process.exit(1);
}
console.log(`connection=${connection.id} hunt=${hunt.id} run=${run.id}\n--- live log (also persisted to prod D1) ---`);

const started = Date.now();
const t = () => `${String(Math.round((Date.now() - started) / 1000)).padStart(4)}s`;
const live = {
  async publish(_runId, event) {
    console.log(`${t()} [${event.level}] ${event.stage}: ${event.message}`);
  },
  async end(_runId, status) {
    console.log(`${t()} === run ${status} ===`);
  },
};

const makeCommandRunner = (repoDir) =>
  createCommandRunner(
    {
      image: process.env.SANDBOX_IMAGE ?? "node:22-slim",
      ociRuntime: process.env.SANDBOX_OCI_RUNTIME ?? "",
      network: "none",
      cpus: "2",
      memory: "2g",
      pidsLimit: 512,
      commandTimeoutMs: 120_000,
    },
    repoDir,
  );

const result = await processRun(run.id, {
  store,
  live,
  // In-process so the orbcode generator can spawn (the --permission fork used on
  // GCP cannot spawn; the local bundle runs the generator in-process instead).
  spawn: inProcessSpawner(createModelClient),
  credentials,
  timeoutMs: Number(process.env.RUN_TIMEOUT_MS ?? 30 * 60_000),
  capabilities: { bash: true, webSearch: false },
  makeCommandRunner,
  webSearch: disabledWebSearch,
  prepareRepo: (job) => (job.repoUrl ? cloneRepo(job.repoUrl) : Promise.resolve(null)),
});

console.log(`\n=== ${result.status}${result.reason ? " (" + result.reason + ")" : ""} · cost $${result.cost.toFixed(4)} · ${result.findings} finding(s) ===`);
const findings = await listFindings(env, org);
for (const f of findings) {
  console.log(`\n■ [${f.severity}/${f.novelty_class ?? "?"}] ${f.title}  (repro ${f.repro_ratio ?? "-"})`);
  console.log(`  where: ${f.location ?? "-"}`);
  console.log(`  mechanism: ${f.mechanism ?? "-"}`);
}
console.log(`\nStored under org ${org} — it will show in /dashboard/hunter for that org once the prod gateway + engine are live.`);
