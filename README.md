# FrostWolf Hunter

The autonomous red-teaming service. It is its own service, on GCP: the public API
worker (`frostwolf-worker`) is Guard plus a thin gateway, and Hunter sits behind
it. See `../HUNTER-PLAN.md` and `../HUNTER-PRD.md`.

```
console / CLI ──▶ worker (auth, gateway) ──▶ Hunter ──▶ Redis   queue + live log
                       ▲                        │ ├──▶ matterai.so  model calls
                       └──── /internal/d1 ◀─────┘        D1 via the worker
```

- **The worker authenticates everything.** It resolves the session cookie or API
  key, then forwards to Hunter with the confirmed tenant in `x-fw-tenant`. Hunter
  never sees a cookie or a customer key.
- **One shared secret**, `HUNTER_SECRET`, used both ways: the worker presents it
  to Hunter, and Hunter presents it to reach D1 through the worker's generic
  `/internal/d1`. Hunter connects to Redis directly with `REDIS_URL`.
- **Redis** holds the run queue and the live log. The queue is a plain Redis
  stream with a consumer group (`src/queue.ts`) — no queueing library — and the
  live log is a list plus pub/sub, so a late watcher replays and a live one
  streams. **D1** holds everything durable: connections, hunts, runs,
  hypotheses, JEV verdicts, findings, and the log's durable copy.
- **Each hunt runs in its own child process**: empty environment, Node's
  permission model (reads only its own code, no writes, no spawning), and a heap
  cap. The parent owns every connection — Redis, D1, and matterai.so — except the
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
5. **exploit** — attacker brain constructs a concrete proof of impact, JEV adjudicates it
6. **verify** — independent N/N reproduction
7. **root_cause** — trace exploit to root cause (stub without repo access)
8. **report** — generate findings with PoC and remediation

The **attacker brain** proposes hypotheses against the declared scope, the
**Plausibility Judge** scores them, and **validate** rules whether the flaw is
real against the cited source. **exploit** then asks a harder question: given
that the flaw is real, construct the concrete attacker input that would trigger
it and trace it through the actual code to its impact — grounded reasoning
against the real cloned repository (via the same agent substrate recon and
synthesis use), not a live request against a booted target. A different judge
rules on that specific construction, not the underlying claim. An independent
reproduction — interpreted by the **verifier brain**, a different model — has to
agree N/N (`VERIFY_N`, default 3) via the **Verification Judge** before anything
is promoted. A run that confirms nothing promotes nothing. Every JEV gate's
verdict is persisted (`hunter_verdicts`), so a promoted finding carries a full
decision trail, including the constructed proof.

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

The easiest way to run Hunter locally is with Docker Compose. This spins up the
full stack: Redis, a dev control-plane (D1-over-SQLite + gateway), and the Hunter
engine.

```bash
# Clone the repo
git clone https://github.com/FrostWolfAI/frostwolf-hunter-engine.git
cd frostwolf-hunter-engine

# Start the full stack
docker compose up --build

# In another shell, start a hunt against any public repo
node devstack/seed.mjs https://github.com/<org>/<repo>
```

`seed.mjs` creates a connection + hunt (scope = that repo), starts a run through
the gateway, streams the live log until the run finishes, then prints the findings.

### Model configuration

The only thing not local is the LLM. By default the stack points at the shared
qwen endpoint. Override it for your own gateway or a local one:

```bash
# .env next to docker-compose.yml
MATTERAI_BASE_URL=http://host.docker.internal:11434/v1   # e.g. a local Ollama
ATTACKER_MODEL=qwen2.5-coder
VERIFIER_MODEL=qwen2.5-coder
JUDGE_MODEL=qwen2.5-coder
VERIFY_N=1
AGENT_RUNTIME=internal     # or "orbcode"
HUNTER_SECRET=dev-secret
```

To make it fully offline, run a local OpenAI-compatible server (Ollama, llama.cpp,
vLLM) and point `MATTERAI_BASE_URL` at it.

### Run without Docker

```bash
cp .env.example .env     # REDIS_URL, HUNTER_SECRET, MATTERAI_API_KEY, model names
npm install
npm run dev              # builds, then starts
```

Create the tables once (both migrations, in order):

```bash
cd ../frostwolf-worker
npx wrangler d1 execute frostwolf --remote --file ../frostwolf-hunter-engine/migrations/0001_hunter.sql
npx wrangler d1 execute frostwolf --remote --file ../frostwolf-hunter-engine/migrations/0002_hunter_verdicts.sql
```

Then on the worker: `wrangler secret put HUNTER_SECRET` (same value) and set
`HUNTER_URL` to wherever this service is reachable.

```bash
docker build -t frostwolf-hunter . && docker run --env-file .env -p 8080:8080 frostwolf-hunter
```

## Layout

| Path | What |
|---|---|
| `src/index.ts` | Entry: HTTP API, Redis stream queue, worker pool. |
| `src/routes.ts` | The API the gateway forwards to. |
| `src/queue.ts` | The run queue, as a native Redis stream + consumer group. |
| `src/runner.ts` | One run: spawn the child, relay events/verdicts/findings, write status. |
| `src/sandbox.ts` | The sandboxed child process, and the credentials handoff. |
| `src/egress-proxy.ts` | OS-level egress boundary: scoped proxy enforcing the allowlist. |
| `src/exploit.ts` | Proof of impact: the attacker model constructs a concrete demonstration, grounded in the real code; no live execution. |
| `src/pipeline.ts`, `src/state-machine.ts`, `src/stages/` | What runs inside the sandbox: the eight stages. |
| `src/judge.ts` | The JEV judge call: structured verdict, fail-closed on anything that doesn't parse. |
| `src/scope.ts` | The egress allowlist check. |
| `src/models/` | `ModelClient`, the matterai.so client, and the Clef stub. |
| `src/live.ts` | The live log in Redis. |
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
