# Local end-to-end stack

Run the whole of Hunter on your machine — no Cloudflare, no GCP — for end-to-end
testing. Three containers: **Redis** (queue + live log), a **dev control-plane**
that stands in for the Cloudflare worker (D1-over-SQLite + the `/v1/hunter/*`
gateway, `dev-worker.mjs`), and the **Hunter engine**.

```
host ──▶ control-plane :8787  ──(x-fw-tenant + secret)──▶  hunter :8080
            │  /v1/hunter/*  (gateway)                         │  queue + run engine
            │  /internal/d1  (SQLite)  ◀───────────────────────┘  reads/writes D1
            └─ volume: d1-data                              redis :6379 (queue/live log)
```

## Run it

```bash
# from the engine repo root
docker compose up --build

# in another shell: start a hunt against any public repo and watch it live
node devstack/seed.mjs https://github.com/<org>/<repo>
```

`seed.mjs` creates a connection + hunt (scope = that repo), starts a run through the
gateway, streams the live log until the run finishes, then prints the findings.

## The model

The only thing not local is the LLM. By default the stack points at the shared qwen
endpoint (`MATTERAI_BASE_URL`); override it for your own gateway or a local one:

```bash
# .env next to docker-compose.yml
MATTERAI_BASE_URL=http://host.docker.internal:11434/v1   # e.g. a local Ollama
ATTACKER_MODEL=qwen2.5-coder
VERIFIER_MODEL=qwen2.5-coder
JUDGE_MODEL=qwen2.5-coder
VERIFY_N=1
AGENT_RUNTIME=internal     # or "orbcode" (see below)
HUNTER_SECRET=dev-secret
```

To make it fully offline, run a local OpenAI-compatible server (Ollama, llama.cpp,
vLLM) and point `MATTERAI_BASE_URL` at it.

## Generator runtime

- `AGENT_RUNTIME=internal` (default) — the built-in agent loop. No extra deps.
- `AGENT_RUNTIME=orbcode` — drive the orbcode harness as the generator substrate.
  Install it in the hunter image and set `ORBCODE_BIN` (orbcode is invoked headless
  with `--json --require-model --output-file`, and Hunter asserts the model it ran).

## What this is / isn't

It reproduces only the two worker surfaces the engine depends on (the D1 loan and the
gateway), backed by SQLite and a single fixed `dev-tenant`. There is no Google OAuth,
no sessions, no metering — it exists purely to exercise the engine and its pipeline
end to end. Production uses the real Cloudflare worker (`frostwolf-worker`).

## Reset

```bash
docker compose down -v   # also drops the Redis and SQLite volumes
```
