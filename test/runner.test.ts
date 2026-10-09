import { describe, expect, it } from "vitest";
import {
  createConnection,
  createHunt,
  getFinding,
  getHunt,
  getRun,
  listEvents,
  listFindings,
  startRun,
  stopHunt,
  revokeConnection,
  type Env,
} from "../src/data/db.js";
import type { Live } from "../src/live.js";
import { processRun } from "../src/runner.js";
import { inProcessSpawner, type Spawner } from "../src/sandbox.js";
import { createStore, type Store } from "../src/store.js";
import type { PreparedRepo } from "../src/repo.js";
import type { RunEvent, RunStatus } from "../src/types.js";
import { baseToolDeps, FAKE_CREDENTIALS, fakeTargetFetch, scriptedModel, type ScriptOutcomes } from "./fakes.js";
import { createFixtureRepo, memoryEnv } from "./helpers.js";

const TENANT = "tenant_acme";
const REPO = "https://github.com/acme/app";

/** A hunt with a run waiting, scoped to a repo (or an overridden scope). */
async function seed(env: Env, scope: Record<string, unknown> = { repo: REPO }) {
  const connection = await createConnection(env, TENANT, {
    provider: "github",
    repos: ["acme/app"],
    runtime: {},
  });
  const hunt = await createHunt(env, TENANT, {
    connection_id: connection.id,
    mode: "oneshot",
    scope,
    depth: "standard",
    policy: {},
  });
  const run = await startRun(env, TENANT, hunt!.id);
  return { connection, hunt: hunt!, run: run! };
}

function fakeLive() {
  const events: RunEvent[] = [];
  const ended: RunStatus[] = [];
  const live: Live = {
    async publish(_runId, event) {
      events.push(event);
    },
    async end(_runId, status) {
      ended.push(status);
    },
  };
  return { live, events, ended };
}

const TIMEOUT_MS = 10_000;

/** Runs the real pipeline against a scripted model, a fixture repo, and a fake target. */
function scriptedSpawner(outcomes: ScriptOutcomes = {}): Spawner {
  return inProcessSpawner(() => scriptedModel(outcomes), fakeTargetFetch);
}

/** A prepareRepo that hands each run its own fixture checkout, as cloneRepo would. */
const fixturePrepare = async (): Promise<PreparedRepo> => createFixtureRepo();

describe("processRun — white-box discovery", () => {
  it("reads the repo, synthesises, validates, independently verifies, and promotes a finding", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const { live, events, ended } = fakeLive();

    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    expect(result.status).toBe("completed");
    expect(result.findings).toBe(1);
    expect(result.cost).toBeGreaterThan(0);

    const stored = await getRun(env, TENANT, run.id);
    expect(stored?.status).toBe("completed");

    const findings = await listFindings(env, TENANT);
    expect(findings).toHaveLength(1);
    const finding = await getFinding(env, TENANT, findings[0]!.id);
    expect(finding?.repro_ratio).toBe(`${FAKE_CREDENTIALS.verifyN}/${FAKE_CREDENTIALS.verifyN}`);
    expect(finding?.mechanism).toContain("client-supplied");
    expect(finding?.location).toContain("src/auth.js");
    expect(finding?.remediation).toContain("session");

    // Live and durable logs carry the same lines.
    const durable = await listEvents(env, TENANT, run.id, 0);
    expect(durable.length).toBe(events.length);
    expect(ended).toEqual(["completed"]);

    // The full decision trail is persisted: plausibility, success adjudication,
    // the exploit stage's proof adjudication, then one verification per
    // independent reproduction.
    const verdicts = await env.DB.prepare(
      "SELECT gate FROM hunter_verdicts WHERE run_id = ?1 ORDER BY created_at",
    )
      .bind(run.id)
      .all<{ gate: string }>();
    expect(verdicts.results.map((v) => v.gate)).toEqual([
      "plausibility_judge",
      "success_adjudicator",
      "exploit_adjudicator",
      "verification_judge",
      "verification_judge",
    ]);

    const hypothesis = await env.DB.prepare(
      "SELECT status FROM hunter_hypotheses WHERE run_id = ?1",
    )
      .bind(run.id)
      .first<{ status: string }>();
    expect(hypothesis?.status).toBe("confirmed");
  });

  it("promotes nothing when the plausibility judge drops the hypothesis", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner({ plausibility: "fail" }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    expect(result.status).toBe("completed");
    expect(result.findings).toBe(0);
    const h = await env.DB.prepare("SELECT status FROM hunter_hypotheses WHERE run_id = ?1")
      .bind(run.id)
      .first<{ status: string }>();
    expect(h?.status).toBe("dropped");
  });

  it("promotes nothing when the code does not bear out the flaw (adjudicator fail)", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner({ adjudicator: "fail" }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.findings).toBe(0);
    const h = await env.DB.prepare("SELECT status FROM hunter_hypotheses WHERE run_id = ?1")
      .bind(run.id)
      .first<{ status: string }>();
    expect(h?.status).toBe("falsified");
  });

  it("drops a confirmed hypothesis the attacker brain cannot turn into a concrete proof", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner({ provable: false }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.findings).toBe(0);
    const h = await env.DB.prepare("SELECT status FROM hunter_hypotheses WHERE run_id = ?1")
      .bind(run.id)
      .first<{ status: string }>();
    expect(h?.status).toBe("falsified");
  });

  it("drops a confirmed hypothesis whose constructed proof the judge rejects", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      // The attacker brain constructs something, but the exploit judge is not
      // convinced it actually traverses the cited code to the claimed impact.
      spawn: scriptedSpawner({ exploitAdjudicator: "fail" }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.findings).toBe(0);
    const h = await env.DB.prepare("SELECT status FROM hunter_hypotheses WHERE run_id = ?1")
      .bind(run.id)
      .first<{ status: string }>();
    expect(h?.status).toBe("falsified");
  });

  it("carries the constructed proof into the promoted finding's evidence", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.findings).toBe(1);
    const findings = await listFindings(env, TENANT);
    const finding = await getFinding(env, TENANT, findings[0]!.id);
    expect(finding?.evidence).toContain("Proof of impact");
    expect(finding?.evidence).toContain("GET /api/profile");
    expect(finding?.evidence).toContain("victim's profile data");
  });

  it("falsifies when the independent verifier does not reproduce N/N", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      // Attacker confirms, but the independent verifier disagrees — not N/N.
      spawn: scriptedSpawner({ verifierExists: false }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.findings).toBe(0);
    const h = await env.DB.prepare("SELECT status FROM hunter_hypotheses WHERE run_id = ?1")
      .bind(run.id)
      .first<{ status: string }>();
    expect(h?.status).toBe("falsified");
  });

  it("refuses a hunt with no repository in scope, before any model call", async () => {
    const env = memoryEnv();
    const { run } = await seed(env, {});
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: async () => null,
    });
    expect(result.status).toBe("failed");
    const stored = await getRun(env, TENANT, run.id);
    expect(stored?.stage).toBe("intake");
  });

  it("fails closed, before cloning, when AI inference is not configured", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: { ...FAKE_CREDENTIALS, aiApiKey: "" },
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("ai_not_configured");
  });

  it("fails the run closed when the clone fails", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    let spawned = false;
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: () => {
        spawned = true;
        return { exited: Promise.resolve(), kill: () => undefined };
      },
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: async () => {
        throw new Error("not found");
      },
    });
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("repo_unavailable");
    expect(spawned).toBe(false);
  });

  it("never starts a run whose connection was revoked", async () => {
    const env = memoryEnv();
    const { run, connection } = await seed(env);
    await revokeConnection(env, TENANT, connection.id);
    let spawned = false;
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: () => {
        spawned = true;
        return { exited: Promise.resolve(), kill: () => undefined };
      },
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.status).toBe("failed");
    expect(spawned).toBe(false);
  });

  it("does not start a run that was stopped while queued", async () => {
    const env = memoryEnv();
    const { run, hunt } = await seed(env);
    await stopHunt(env, TENANT, hunt.id);
    let spawned = false;
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: () => {
        spawned = true;
        return { exited: Promise.resolve(), kill: () => undefined };
      },
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.status).toBe("stopped");
    expect(spawned).toBe(false);
  });

  it("kills a run that exceeds its time budget", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    let killed = false;
    const hang: Spawner = () => {
      let release: () => void = () => undefined;
      const exited = new Promise<void>((resolve) => (release = resolve));
      return { exited, kill: () => { killed = true; release(); } };
    };
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: hang,
      credentials: FAKE_CREDENTIALS,
      timeoutMs: 20,
      prepareRepo: fixturePrepare,
    });
    expect(killed).toBe(true);
    expect(result.status).toBe("failed");
    expect(result.reason).toMatch(/time budget/);
  });

  it("fails a run whose child exits without finishing", async () => {
    const env = memoryEnv();
    const { run } = await seed(env);
    const result = await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: () => ({ exited: Promise.resolve(), kill: () => undefined }),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });
    expect(result.status).toBe("failed");
    expect(result.reason).toMatch(/without finishing/);
  });

  it("returns the hunt to idle once its only run finishes", async () => {
    const env = memoryEnv();
    const { hunt, run } = await seed(env);
    expect((await getHunt(env, TENANT, hunt.id))?.status).toBe("active");

    await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    expect((await getHunt(env, TENANT, hunt.id))?.status).toBe("idle");
  });

  it("keeps the hunt active while a second run of it is still queued", async () => {
    const env = memoryEnv();
    const { hunt, run } = await seed(env);
    const second = await startRun(env, TENANT, hunt.id);

    await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    // The first run finished, but the second is still queued, so the hunt stays
    // active rather than flipping back to idle under it.
    expect((await getHunt(env, TENANT, hunt.id))?.status).toBe("active");

    await processRun(second!.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    expect((await getHunt(env, TENANT, hunt.id))?.status).toBe("idle");
  });

  it("leaves a stopped hunt stopped when its run finishes afterwards", async () => {
    const env = memoryEnv();
    const { hunt, run } = await seed(env);
    await stopHunt(env, TENANT, hunt.id);

    await processRun(run.id, {
      store: createStore(env),
      ...baseToolDeps,
      live: fakeLive().live,
      spawn: scriptedSpawner(),
      credentials: FAKE_CREDENTIALS,
      timeoutMs: TIMEOUT_MS,
      prepareRepo: fixturePrepare,
    });

    expect((await getHunt(env, TENANT, hunt.id))?.status).toBe("stopped");
  });
});
