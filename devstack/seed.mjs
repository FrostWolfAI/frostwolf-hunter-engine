/**
 * Start one hunt against the local stack and stream it to completion.
 *
 *   node devstack/seed.mjs <repoUrl> [gatewayUrl]
 *
 * Talks to the dev control-plane's gateway (default http://localhost:8787), which
 * injects the dev tenant — exactly the path the console/CLI take in production.
 */

const repo = process.argv[2];
const base = (process.argv[3] ?? process.env.GATEWAY_URL ?? "http://localhost:8787").replace(/\/$/, "");
if (!repo) {
  console.error("usage: node devstack/seed.mjs <repoUrl> [gatewayUrl]");
  process.exit(2);
}

async function api(method, path, body) {
  const res = await fetch(`${base}${path}`, {
    method,
    headers: body ? { "content-type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

const { connection } = await api("POST", "/v1/hunter/connections", { provider: "github", repos: [repo] });
console.log(`connection: ${connection.id}`);
const { hunt } = await api("POST", "/v1/hunter/hunts", { connection_id: connection.id, scope: { repo } });
console.log(`hunt: ${hunt.id}`);
const started = await api("POST", `/v1/hunter/hunts/${hunt.id}/start`);
const runId = started.run.id;
console.log(`run: ${runId} (status ${started.run.status})\n--- live log ---`);

// Stream the live log until the run ends.
const res = await fetch(`${base}/v1/hunter/runs/${runId}/stream`);
const reader = res.body.getReader();
const decoder = new TextDecoder();
let buf = "";
for (;;) {
  const { done, value } = await reader.read();
  if (done) break;
  buf += decoder.decode(value, { stream: true });
  let nl;
  while ((nl = buf.indexOf("\n")) !== -1) {
    const line = buf.slice(0, nl).trim();
    buf = buf.slice(nl + 1);
    if (line.startsWith("data:")) {
      try {
        const e = JSON.parse(line.slice(5).trim());
        console.log(`[${e.level ?? "info"}] ${e.stage ?? ""}: ${e.message ?? ""}`);
      } catch {
        // heartbeat or non-JSON frame
      }
    }
  }
}

const { findings } = await api("GET", "/v1/hunter/findings");
console.log(`\n--- findings: ${findings.length} ---`);
for (const f of findings) {
  console.log(`\n■ [${f.severity}/${f.novelty_class ?? "?"}] ${f.title}  (repro ${f.repro_ratio ?? "-"})`);
  console.log(`  where: ${f.location ?? "-"}`);
  console.log(`  mechanism: ${f.mechanism ?? "-"}`);
}
