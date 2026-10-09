import { describe, expect, it } from "vitest";
import type { Env } from "../src/data/db.js";
import { createHandler } from "../src/routes.js";
import { processRun } from "../src/runner.js";
import { inProcessSpawner } from "../src/sandbox.js";
import { baseToolDeps, FAKE_CREDENTIALS, fakeTargetFetch, scriptedModel } from "./fakes.js";
import { createStore } from "../src/store.js";
import { createFixtureRepo, memoryEnv } from "./helpers.js";
import type { PreparedRepo } from "../src/repo.js";

const SECRET = "test-hunter-secret";

/** Hands each run its own fixture checkout, as cloneRepo would in production. */
const fixturePrepare = async (): Promise<PreparedRepo> => createFixtureRepo();

/** A Hunter wired to an in-memory database and a recording queue. */
function harness(options: { failEnqueue?: boolean } = {}) {
  const env = memoryEnv();
  const enqueued: string[] = [];
  const handler = createHandler({
    secret: SECRET,
    env,
    enqueue: async (runId) => {
      if (options.failEnqueue === true) {
        throw new Error("redis down");
      }
      enqueued.push(runId);
    },
    liveStream: () => new Response("data: {\"message\":\"live\"}\n\n").body!,
  });

  /** Call as the gateway does: the shared secret plus the confirmed tenant. */
  const call = (
    method: string,
    path: string,
    body?: unknown,
    tenant = "tenant_acme",
    secret = SECRET,
  ) =>
    handler(
      new Request(`http://hunter${path}`, {
        method,
        headers: {
          authorization: `Bearer ${secret}`,
          ...(tenant === "" ? {} : { "x-fw-tenant": tenant }),
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
    );

  const json = async <T>(response: Response): Promise<T> => (await response.json()) as T;
  return { env, enqueued, call, json };
}

type H = ReturnType<typeof harness>;

async function makeHunt(h: H, tenant = "tenant_acme") {
  const { connection } = await h.json<{ connection: { id: string } }>(
    await h.call("POST", "/v1/hunter/connections", { provider: "github", repos: ["acme/app"] }, tenant),
  );
  const { hunt } = await h.json<{ hunt: { id: string } }>(
    await h.call(
      "POST",
      "/v1/hunter/hunts",
      { connection_id: connection.id, scope: { repo: "https://github.com/acme/app" } },
      tenant,
    ),
  );
  return { connectionId: connection.id, huntId: hunt.id };
}

async function startAndRun(h: H, huntId: string, env: Env) {
  const { run } = await h.json<{ run: { id: string } }>(
    await h.call("POST", `/v1/hunter/hunts/${huntId}/start`),
  );
  await processRun(run.id, {
    store: createStore(env),
    ...baseToolDeps,
    live: { publish: async () => undefined, end: async () => undefined },
    spawn: inProcessSpawner(() => scriptedModel({}), fakeTargetFetch),
    credentials: FAKE_CREDENTIALS,
    timeoutMs: 10_000,
    prepareRepo: fixturePrepare,
  });
  return run.id;
}

describe("trust", () => {
  it("answers health without a secret", async () => {
    const h = harness();
    const response = await h.call("GET", "/health", undefined, "", "");
    expect(response.status).toBe(200);
  });

  it("refuses anything not from the gateway", async () => {
    const h = harness();
    expect((await h.call("GET", "/v1/hunter/hunts", undefined, "tenant_acme", "wrong")).status).toBe(401);
    expect((await h.call("GET", "/v1/hunter/hunts", undefined, "tenant_acme", "")).status).toBe(401);
  });

  it("refuses a request that carries no confirmed tenant", async () => {
    const h = harness();
    expect((await h.call("GET", "/v1/hunter/hunts", undefined, "")).status).toBe(404);
  });
});

describe("the platform, end to end", () => {
  it("connects, hunts, runs, and surfaces a finding", async () => {
    const h = harness();
    const { huntId } = await makeHunt(h);

    const started = await h.call("POST", `/v1/hunter/hunts/${huntId}/start`);
    expect(started.status).toBe(202);
    const { run } = await h.json<{ run: { id: string; status: string } }>(started);
    expect(run.status).toBe("queued");
    expect(h.enqueued).toEqual([run.id]);

    await processRun(run.id, {
      store: createStore(h.env),
      ...baseToolDeps,
      live: { publish: async () => undefined, end: async () => undefined },
      spawn: inProcessSpawner(() => scriptedModel({}), fakeTargetFetch),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: 10_000,
      prepareRepo: fixturePrepare,
    });

    const { runs } = await h.json<{ runs: Array<{ status: string }> }>(
      await h.call("GET", `/v1/hunter/hunts/${huntId}/runs`),
    );
    expect(runs[0]!.status).toBe("completed");

    const { findings } = await h.json<{ findings: Array<{ id: string; status: string }> }>(
      await h.call("GET", "/v1/hunter/findings"),
    );
    expect(findings).toHaveLength(1);

    const triaged = await h.call("PATCH", `/v1/hunter/findings/${findings[0]!.id}`, { status: "confirmed" });
    expect((await h.json<{ finding: { status: string } }>(triaged)).finding.status).toBe("confirmed");

    const analytics = await h.json<{ findings_total: number; confirmed: number }>(
      await h.call("GET", "/v1/hunter/analytics"),
    );
    expect(analytics).toMatchObject({ findings_total: 1, confirmed: 1 });
  });

  it("replays a finished run's log from the database", async () => {
    const h = harness();
    const { huntId } = await makeHunt(h);
    const runId = await startAndRun(h, huntId, h.env);

    const response = await h.call("GET", `/v1/hunter/runs/${runId}/stream`);
    expect(response.headers.get("content-type")).toContain("text/event-stream");
    const text = await response.text();
    expect(text).toContain("scope locked to repository");
  });

  it("streams a run that is still going live", async () => {
    const h = harness();
    const { huntId } = await makeHunt(h);
    const { run } = await h.json<{ run: { id: string } }>(
      await h.call("POST", `/v1/hunter/hunts/${huntId}/start`),
    );
    const text = await (await h.call("GET", `/v1/hunter/runs/${run.id}/stream`)).text();
    expect(text).toContain('"message":"live"');
  });

  it("serves a finished run's log as a plain page of JSON, not just the stream", async () => {
    const h = harness();
    const { huntId } = await makeHunt(h);
    const runId = await startAndRun(h, huntId, h.env);

    const { run, events } = await h.json<{
      run: { id: string; status: string };
      events: Array<{ seq: number; message: string }>;
    }>(await h.call("GET", `/v1/hunter/runs/${runId}/events`));

    expect(run.status).toBe("completed");
    expect(events.length).toBeGreaterThan(0);
    expect(events.some((e) => e.message.includes("scope locked to repository"))).toBe(true);

    // Paging past the last seq returns nothing new rather than replaying.
    const lastSeq = events[events.length - 1]!.seq;
    const { events: rest } = await h.json<{ events: unknown[] }>(
      await h.call("GET", `/v1/hunter/runs/${runId}/events?after=${lastSeq}`),
    );
    expect(rest).toHaveLength(0);
  });

  it("marks the run failed when the queue is down", async () => {
    const h = harness({ failEnqueue: true });
    const { huntId } = await makeHunt(h);
    const response = await h.call("POST", `/v1/hunter/hunts/${huntId}/start`);
    expect(response.status).toBe(503);
    const { runs } = await h.json<{ runs: Array<{ status: string }> }>(
      await h.call("GET", `/v1/hunter/hunts/${huntId}/runs`),
    );
    expect(runs[0]!.status).toBe("failed");
  });
});

describe("tenant isolation", () => {
  it("shows one tenant nothing of another's", async () => {
    const h = harness();
    const { connectionId, huntId } = await makeHunt(h, "tenant_acme");
    const runId = await startAndRun(h, huntId, h.env);
    const other = "tenant_globex";

    const get = (path: string) => h.call("GET", path, undefined, other);
    expect((await h.json<{ hunts: unknown[] }>(await get("/v1/hunter/hunts"))).hunts).toHaveLength(0);
    expect((await h.json<{ findings: unknown[] }>(await get("/v1/hunter/findings"))).findings).toHaveLength(0);
    expect((await h.json<{ connections: unknown[] }>(await get("/v1/hunter/connections"))).connections).toHaveLength(0);
    expect((await get(`/v1/hunter/hunts/${huntId}`)).status).toBe(404);
    expect((await get(`/v1/hunter/hunts/${huntId}/runs`)).status).toBe(404);
    expect((await get(`/v1/hunter/runs/${runId}/stream`)).status).toBe(404);
    expect((await get(`/v1/hunter/runs/${runId}/events`)).status).toBe(404);

    expect((await h.call("POST", `/v1/hunter/hunts/${huntId}/start`, undefined, other)).status).toBe(404);
    expect((await h.call("POST", `/v1/hunter/hunts/${huntId}/stop`, undefined, other)).status).toBe(404);
    expect(
      (await h.call("POST", "/v1/hunter/hunts", { connection_id: connectionId }, other)).status,
    ).toBe(404);
    expect((await h.call("DELETE", `/v1/hunter/connections/${connectionId}`, undefined, other)).status).toBe(404);
  });
});
