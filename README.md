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

Repository access is deferred, so three of the eight stages are honest, explicit
stubs rather than fabricated output — **recon** (needs code and docs), **chain**
(needs multiple confirmed findings), and **root_cause** (needs source to trace an
exploit back to). They log why they are skipped and advance.

The rest is real: the **attacker brain** proposes one reconnaissance-class
hypothesis against the declared scope (there is no code yet to ground anything
riskier in), the **Plausibility Judge** scores it, a non-destructive probe runs
against the declared target through a scope-enforcing `fetch`, the **Success
Adjudicator** reads the result, and an independent reproduction — interpreted by
the **verifier brain**, a different model — has to agree N/N (`VERIFY_N`,
default 3) via the **Verification Judge** before anything is promoted. A run that
confirms nothing promotes nothing. Every JEV gate's verdict is persisted
(`hunter_verdicts`), so a promoted finding carries a full decision trail.

**A known gap:** scope enforcement (`src/scope.ts`) is application-level today —
every stage's outbound call goes through a `fetch` wrapper that refuses anything
outside the declared hosts. It is *not* yet an OS-level network boundary: Node's
permission model restricts the filesystem and child processes but has no network
flag, so a compromised stage could still open a raw socket. What runs inside the
sandbox today is code this service shipped, not arbitrary code, so the wrapper is
a real control for that. An OS-level egress boundary is required before anything
less trusted — repo-derived code, or a fully autonomous request-crafting loop —
runs in there, and is not built yet.

## Run it

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
| `src/pipeline.ts`, `src/state-machine.ts`, `src/stages/` | What runs inside the sandbox: the eight stages. |
| `src/judge.ts` | The JEV judge call: structured verdict, fail-closed on anything that doesn't parse. |
| `src/scope.ts` | The egress allowlist check — see the caveat above. |
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
