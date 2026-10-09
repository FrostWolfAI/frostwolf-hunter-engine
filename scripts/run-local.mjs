/**
 * Run one real hunt locally against a public repo, with no Redis / D1 / worker.
 * It clones the repo and drives the actual pipeline (recon → synthesis → validate
 * → verify → root_cause → report) with a real model, printing the live log and the
 * findings. For an authorized assessment of a repo you control / designate.
 *
 *   node scripts/run-local.mjs <repoUrl> <baseUrl> <model>
 */
import { cloneRepo } from "../dist/repo.js";
import { executeRun } from "../dist/pipeline.js";

const repoUrl = process.argv[2];
const baseUrl = process.argv[3];
const model = process.argv[4];
if (!repoUrl || !baseUrl || !model) {
  console.error("usage: run-local.mjs <repoUrl> <baseUrl> <model>");
  process.exit(2);
}

const credentials = {
  aiProvider: "matterai",
  aiBaseUrl: baseUrl,
  aiApiKey: "no-key",            // server needs none; header is sent but ignored
  attackerModel: model,
  verifierModel: model,          // same model here (one endpoint); independence is weaker
  judgeModel: model,
  verifyN: Number(process.env.VERIFY_N ?? 1),
  costPer1kTokensUsd: 0,
  maxRunTokens: 2_000_000,       // cost governor: the agent stops once spent
  agentRuntime: process.env.AGENT_RUNTIME === "orbcode" ? "orbcode" : "internal",
  orbcodeBin: process.env.ORBCODE_BIN ?? "",
};

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
await repo.cleanup();
