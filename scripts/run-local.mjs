/**
 * Run one real hunt locally against a public repo, with no Redis / D1 / worker.
 * It clones the repo and drives the actual pipeline (recon → synthesis → validate
 * → verify → root_cause → report) with a real model, printing the live log and the
 * findings. For an authorized assessment of a repo you control / designate.
 *
 * Config comes from the environment (load an .env with `node --env-file=.env`);
 * the old positional args still work as overrides:
 *
 *   node --env-file=.env scripts/run-local.mjs <repoUrl>
 *   node scripts/run-local.mjs <repoUrl> <baseUrl> <model>   # legacy, single model
 *
 * Env read: MATTERAI_BASE_URL, MATTERAI_API_KEY, ATTACKER_MODEL, VERIFIER_MODEL,
 * JUDGE_MODEL, JUDGE_PROVIDER (default skip), JUDGE_BASE_URL, VERIFY_N, AGENT_RUNTIME.
 */
import { writeFileSync } from "node:fs";
import { cloneRepo } from "../dist/repo.js";
import { executeRun } from "../dist/pipeline.js";

const repoUrl = process.argv[2];
const baseUrl = process.argv[3] ?? process.env.MATTERAI_BASE_URL;
const modelArg = process.argv[4]; // legacy: one model for every role
const attackerModel = modelArg ?? process.env.ATTACKER_MODEL;
const verifierModel = modelArg ?? process.env.VERIFIER_MODEL ?? attackerModel;
const judgeProvider = process.env.JUDGE_PROVIDER ?? "skip";
if (!repoUrl || !baseUrl || !attackerModel) {
  console.error(
    "usage: node --env-file=.env scripts/run-local.mjs <repoUrl>\n" +
      "   or: node scripts/run-local.mjs <repoUrl> <baseUrl> <model>\n" +
      "need a repo URL, a base URL (arg or MATTERAI_BASE_URL), and a model (arg or ATTACKER_MODEL).",
  );
  process.exit(2);
}

const credentials = {
  aiProvider: process.env.MODEL_PROVIDER === "clef" ? "clef" : "matterai",
  aiBaseUrl: baseUrl,
  aiApiKey: process.env.MATTERAI_API_KEY ?? "no-key",
  attackerModel,
  verifierModel,
  judgeModel: process.env.JUDGE_MODEL ?? attackerModel,
  judgeProvider,                 // "skip" (default) calls no model; "chat"/"gliner" turn the JEV gates on
  judgeBaseUrl: process.env.JUDGE_BASE_URL ?? "",
  verifyN: Number(process.env.VERIFY_N ?? 1),
  costPer1kTokensUsd: 0,
  maxRunTokens: Number(process.env.MAX_RUN_TOKENS ?? 2_000_000), // cost governor: the agent stops once spent
  agentRuntime:
    process.env.AGENT_RUNTIME === "internal"
      ? "internal"
      : process.env.AGENT_RUNTIME === "claude"
        ? "claude"
        : process.env.AGENT_RUNTIME === "codex"
          ? "codex"
          : "orbcode", // default
  orbcodeBin: process.env.ORBCODE_BIN ?? "",
};
if (credentials.agentRuntime === "orbcode" && credentials.orbcodeBin.length === 0) {
  console.error("AGENT_RUNTIME=orbcode (the default) needs ORBCODE_BIN set to bin/orbcode.js.");
  process.exit(2);
}
console.log(
  `models: attacker=${attackerModel} verifier=${verifierModel} judge=${judgeProvider}` +
    (judgeProvider === "skip" ? " (no judge-model call)" : ` (${credentials.judgeModel})`),
);

console.log(`cloning ${repoUrl} …`);
const repo = await cloneRepo(repoUrl);
console.log(`cloned to ${repo.dir}`);
console.log(`generator runtime: ${credentials.agentRuntime}${credentials.agentRuntime==="orbcode"?" ("+credentials.orbcodeBin+")":""}`);

const input = {
  job: {
    run_id: "local-1", hunt_id: "local", tenant_id: "local",
    provider: "github", repos: [], repoUrl,
    scope: { repo: repoUrl }, depth: "standard", policy: {},
  },
  credentials,
  capabilities: { bash: false, webSearch: false },
  repoDir: repo.dir,
};

const findings = [];
let spend = 0;
const started = Date.now();
const t = (ts) => `${String(Math.round((Date.parse(ts) - started) / 1000)).padStart(4)}s`;

await executeRun(input, (m) => {
  if (m.type === "event") {
    if (m.event.level === "debug") console.log(`   ${t(m.event.ts)} · ${m.event.stage} · ${m.event.message}`);
    else console.log(`${t(m.event.ts)} [${m.event.level}] ${m.event.stage}: ${m.event.message}`);
  } else if (m.type === "hypothesis") {
    console.log(`  ↳ hypothesis ${m.hypothesis.code}: ${m.hypothesis.rationale}`);
  } else if (m.type === "verdict") {
    console.log(`  ⚖ ${m.gate}${m.hypothesis_code ? " " + m.hypothesis_code : ""}: ${m.verdict.verdict} (${m.verdict.confidence})`);
  } else if (m.type === "finding") {
    findings.push(m.finding);
  } else if (m.type === "spend") {
    spend += m.usd;
  } else if (m.type === "done") {
    console.log(`\n=== done: ok=${m.ok}${m.reason ? " reason=" + m.reason : ""} ===`);
  }
});

console.log(`\nFINDINGS: ${findings.length}`);
for (const f of findings) {
  console.log(`\n■ [${f.severity}/${f.novelty_class}] ${f.title}  (repro ${f.repro_ratio})`);
  console.log(`  where: ${f.location}`);
  console.log(`  mechanism: ${f.mechanism}`);
  console.log(`  fix: ${f.remediation}`);
}

// Save the full result so it is never lost in terminal scrollback.
const outPath = process.env.FINDINGS_OUT ?? "hunt-findings.json";
writeFileSync(
  outPath,
  JSON.stringify({ repo: repoUrl, spendUsd: spend, count: findings.length, findings }, null, 2),
);
console.log(`\nSaved ${findings.length} finding(s) to ${outPath}`);

await repo.cleanup();
