# FrostWolf Hunter

The autonomous red-teaming service. It is its own service, on GCP: the public API
worker (`frostwolf-worker`) is Guard plus a thin gateway, and Hunter sits behind
it. See `../HUNTER-PLAN.md` and `../HUNTER-PRD.md`.

```
console / CLI ──▶ worker (auth, gateway) ──▶ Hunter (HTTP API)
                       ▲                        │ ├──▶ matterai.so  model calls
                       └──── /internal/d1 ◀─────┘        D1 via the worker
```

- **The worker authenticates everything.** It resolves the session cookie or API
  key, then forwards to Hunter with the confirmed tenant in `x-fw-tenant`. Hunter
  never sees a cookie or a customer key.
- **One shared secret**, `HUNTER_SECRET`, used both ways: the worker presents it
  to Hunter, and Hunter presents it to reach D1 through the worker's generic
  `/internal/d1`.
- **A hunt is started by a direct API call** (`POST /v1/hunter/hunts/:id/start`)
  and runs in the engine process — no queue, no Redis. The live log is kept in
  memory and streamed over SSE (`src/live.ts`), so a watcher that connects while a
  run is in flight replays the backlog and then follows live; a finished run is
  served from D1. **D1** holds everything durable: connections, hunts, runs,
  hypotheses, JEV verdicts, findings, and the log's durable copy.
- **Each hunt runs in its own child process**: empty environment, Node's
  permission model (reads only its own code, no writes, no spawning), and a heap
  cap. The parent owns every connection — D1 and matterai.so — except the
  one child gets its own run-scoped copy of the model credentials over IPC, never
  through its environment, because it has to make its own model and target calls
  (see `src/sandbox.ts`, `src/types.ts`'s `RunCredentials`). A hunt that is
  stopped from the console, or runs over its budget, is killed.
- **Model calls go through matterai.so** (GLM 5.3 and others), with Clef
  (Cloudflare's model) wired in as a selectable-but-not-yet-live provider
  (`src/models/`). The model id for each role — attacker, verifier, judge — is
  configuration, never hardcoded.

## What actually runs today

The full eight-stage pipeline is built and tested:

1. **intake** — validate scope, budget, credentials
2. **recon** — discover attack surface (stub without repo access)
3. **synthesis** — attacker brain proposes hypotheses
4. **validate** — JEV judges score plausibility, then adjudicate against the real code
5. **exploit** — attacker brain constructs a best-effort proof of impact (never gates)
6. **verify** — independent N/N reproduction
7. **root_cause** — trace exploit to root cause (stub without repo access)
8. **report** — generate findings with PoC and remediation

> **Judge default is `skip`.** `JUDGE_PROVIDER=skip` (the default while the judge
> is being reworked) calls no model and clears every gate, so recon → synthesis →
> validate → verify runs end to end. The generators still explore and `verify`
> still re-derives on an independent model that must agree, so this is not "promote
> everything" — but it is not a truth gate either. Set `JUDGE_PROVIDER=chat` (or
> `gliner`) to turn the JEV judges back on.
>
> **The sandbox is always a container.** `bash` is never disabled by config; it
> runs only inside an isolated container and the host must provide a container
> runtime. There is no host-execution or no-op fallback.

The **attacker brain** proposes hypotheses against the declared scope, the
**Plausibility Judge** scores them, and **validate** rules whether the flaw is
real against the cited source. **exploit** then asks a harder question: given
that the flaw is real, construct the concrete attacker input that would trigger
it and trace it through the actual code to its impact — grounded reasoning
against the real cloned repository (via the same agent substrate recon and
synthesis use), not a live request against a booted target. The construction is
attached to the finding when it succeeds; the exploit stage never drops a
hypothesis, so every confirmed flaw reaches verification whether or not a proof
was built. An independent reproduction — interpreted by the **verifier brain**, a
different model — has to agree N/N (`VERIFY_N`, default 3) before anything is
promoted. A run that confirms nothing promotes nothing. Each gate's verdict is
persisted (`hunter_verdicts`), so a promoted finding carries a decision trail
(pass-through verdicts while the judge is skipped), including the constructed proof.

**What this is not, yet:** nothing here boots a target, opens a socket, or runs
a command against the target. There is no live PoC, only a constructed one. A
real live-fire PoC needs a sandboxed execution surface this run can reach safely
— a container with no host access, and a decision about whether it gets network
egress at all — which does not exist. The `bash` tool (`src/sandbox-exec.ts`,
below) is a real, working, container-isolated command runner, but it is wired to
the generator stages (recon/synthesis exploring the checkout), not to `exploit`.

**OS-level egress boundary:** `src/egress-proxy.ts` provides a scoped egress
proxy that enforces the declared scope on all outbound HTTP/HTTPS traffic. The
sandboxed child routes all network traffic through this proxy via `HTTP_PROXY`/
`HTTPS_PROXY` environment variables, providing a true network boundary that
catches all egress, not just `fetch()` calls.

## Run it locally

The local bundle runs the Hunter **agent** on your machine and writes everything to
**production** — there is no local database, no local Redis, no local control plane.
Storage is prod D1 (reached through the gateway worker), and every record is stamped
with `FW_ORG_ID` so prod knows which org it belongs to.

```bash
git clone https://github.com/FrostWolfAI/frostwolf-hunter-engine.git
cd frostwolf-hunter-engine

# One hunt: clone the repo, run the pipeline, push the results to prod under your org.
FW_ORG_ID=<your-org-id> \
HUNTER_SECRET=<prod shared secret> \
MATTERAI_API_KEY=<model key> \
REPO_URL=https://github.com/<org>/<repo> \
  docker compose run --rm hunter
```

The agent clones `REPO_URL`, runs recon → synthesis → validate → exploit → verify
with the orbcode generator (bundled in the image), writes the connection, hunt, run,
live events, and findings to prod D1 under `FW_ORG_ID`, then exits. It is a one-shot
agent, not a standing service, so it does not auto-restart. Results appear in the
console/dashboard for that org.

### Model configuration

Defaults: `WORKER_URL=https://api.frostwolf.app`, attacker/verifier
`frost-abliterated-cyber-max-1`, `JUDGE_PROVIDER=skip`, `AGENT_RUNTIME=orbcode`.
Override any through the environment:

```bash
MATTERAI_BASE_URL=https://api2.matterai.so/v1
ATTACKER_MODEL=frost-abliterated-cyber-max-1
VERIFIER_MODEL=frost-abliterated-cyber-max-1
VERIFY_N=1
```

### Run without Docker

Run the agent straight from the checkout — it connects to prod by default, so you
only pass your org id, the shared secret, and the model key:

```bash
npm install && npm run build
FW_ORG_ID=<org> HUNTER_SECRET=<secret> MATTERAI_API_KEY=<key> \
ORBCODE_BIN=/path/to/orbcode/bin/orbcode.js \
  node scripts/run-and-push.mjs https://github.com/<org>/<repo>
```

`WORKER_URL` defaults to `https://api.frostwolf.app` and `MATTERAI_BASE_URL` to the
prod matterai endpoint — override them only to point elsewhere.

`node scripts/run-local.mjs <repo>` runs the same pipeline but prints the findings
instead of writing to prod — a quick offline smoke test.

> The same `node dist/index.js` HTTP service runs on **GCP** as the shared
> deployment; the local bundle is the identical image, just pointed at prod D1.
> Prod D1 tables are already applied.

## Layout

| Path | What |
|---|---|
| `src/index.ts` | Entry: the always-on HTTP service; a start call runs the hunt in-process. |
| `src/routes.ts` | The API the gateway forwards to; `start` runs a hunt directly. |
| `src/runner.ts` | One run: spawn the child, relay events/verdicts/findings, write status. |
| `src/sandbox.ts` | The sandboxed child process, and the credentials handoff. |
| `src/egress-proxy.ts` | OS-level egress boundary: scoped proxy enforcing the allowlist. |
| `src/exploit.ts` | Proof of impact: the attacker model constructs a concrete demonstration, grounded in the real code; no live execution. |
| `src/pipeline.ts`, `src/state-machine.ts`, `src/stages/` | What runs inside the sandbox: the eight stages. |
| `src/judge.ts` | The JEV judge call: structured verdict, fail-closed on anything that doesn't parse. |
| `src/scope.ts` | The egress allowlist check. |
| `src/models/` | `ModelClient`, the matterai.so client, and the Clef stub. |
| `src/live.ts` | The in-memory live log + its SSE stream. |
| `src/d1.ts`, `src/data/` | D1 via the worker, and the queries. |

## Verify

```bash
npm test && npm run typecheck
```

Tests run the real pipeline against a scripted `ModelClient` and a fake target
`fetch` (see `test/fakes.ts`) rather than a live matterai.so account or a live
target — nothing in production has that override available. The queue is tested
against an in-memory stand-in for Redis streams; it has not been exercised
against a real Redis yet.
