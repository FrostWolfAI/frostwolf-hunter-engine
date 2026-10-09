import type { Redis } from "ioredis";
import { describe, expect, it } from "vitest";
import { createQueue, startWorker } from "../src/queue.js";
import type { Config } from "../src/config.js";

const CONFIG: Config = {
  port: 0,
  redisUrl: "redis://fake",
  workerUrl: "https://worker.test",
  secret: "s",
  queueName: "test-stream",
  concurrency: 1,
  runTimeoutMs: 1000,
  aiProvider: "matterai",
  aiBaseUrl: "https://matterai.test",
  aiApiKey: "k",
  attackerModel: "a",
  verifierModel: "v",
  judgeModel: "j",
  verifyN: 1,
  costPer1kTokensUsd: 0,
};

/** A real macrotask tick, so a tight polling loop can't starve the test's own timers. */
function tick(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/** Just enough of a Redis stream + consumer group to exercise the queue. */
class FakeRedis {
  private entries: Array<{ id: string; fields: string[] }> = [];
  private seq = 0;
  /** entryId -> owning consumer, for entries claimed but not yet acked. */
  private pending = new Map<string, { consumer: string; claimedAt: number }>();
  private acked = new Set<string>();
  readonly keys = new Map<string, string>();

  async set(key: string, value: string, _ex: "EX", _ttl: number, nx: "NX"): Promise<string | null> {
    if (nx === "NX" && this.keys.has(key)) {
      return null;
    }
    this.keys.set(key, value);
    return "OK";
  }

  async xadd(_stream: string, _id: "*", ...fields: string[]): Promise<string> {
    const id = `${++this.seq}-0`;
    this.entries.push({ id, fields });
    return id;
  }

  async xgroup(): Promise<void> {
    // Fine to be a no-op: this fake has one implicit group.
  }

  async xreadgroup(
    _group: "GROUP",
    _groupName: string,
    consumer: string,
    ..._rest: unknown[]
  ): Promise<[string, [string, string[]][]][] | null> {
    const next = this.entries.find((e) => !this.pending.has(e.id) && !this.acked.has(e.id));
    if (next === undefined) {
      // A real BLOCKing read waits on the socket; yield a real tick here so a
      // caller's own timers (and other promises) still get a turn instead of
      // being starved by a microtask-only polling loop.
      await tick();
      return null;
    }
    this.pending.set(next.id, { consumer, claimedAt: Date.now() });
    return [["test-stream", [[next.id, next.fields]]]];
  }

  async xack(_stream: string, _group: string, id: string): Promise<number> {
    this.acked.add(id);
    this.pending.delete(id);
    return 1;
  }

  async xautoclaim(
    _stream: string,
    _group: string,
    consumer: string,
    minIdleMs: number,
    _start: "0-0",
    ..._rest: unknown[]
  ): Promise<[string, [string, string[]][], string[]]> {
    const now = Date.now();
    const stale = [...this.pending.entries()].find(
      ([id, claim]) => !this.acked.has(id) && now - claim.claimedAt >= minIdleMs,
    );
    if (stale === undefined) {
      await tick();
      return ["0-0", [], []];
    }
    const [id] = stale;
    this.pending.set(id, { consumer, claimedAt: now });
    const entry = this.entries.find((e) => e.id === id)!;
    return ["0-0", [[id, entry.fields]], []];
  }

  get ackedCount(): number {
    return this.acked.size;
  }
}

describe("createQueue", () => {
  it("adds an entry carrying the run id", async () => {
    const redis = new FakeRedis();
    const queue = createQueue(CONFIG, redis as unknown as Redis);
    await queue.add("run_1");
    // A second enqueue of the same run is a no-op, guarded by the dedup key.
    await queue.add("run_1");

    const worker = startWorker(CONFIG, redis as unknown as Redis, async (runId) => {
      expect(runId).toBe("run_1");
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    await worker.close();
    expect(redis.ackedCount).toBe(1);
  });
});

describe("startWorker", () => {
  it("processes an enqueued run exactly once and acknowledges it", async () => {
    const redis = new FakeRedis();
    const queue = createQueue(CONFIG, redis as unknown as Redis);
    await queue.add("run_a");

    const seen: string[] = [];
    const worker = startWorker(CONFIG, redis as unknown as Redis, async (runId) => {
      seen.push(runId);
    });

    await new Promise((resolve) => setTimeout(resolve, 20));
    await worker.close();

    expect(seen).toEqual(["run_a"]);
  });

  it("keeps processing after a handler throws, and still acknowledges the entry", async () => {
    const redis = new FakeRedis();
    const queue = createQueue(CONFIG, redis as unknown as Redis);
    await queue.add("run_b");
    await queue.add("run_c");

    const seen: string[] = [];
    const worker = startWorker(CONFIG, redis as unknown as Redis, async (runId) => {
      seen.push(runId);
      if (runId === "run_b") {
        throw new Error("boom");
      }
    });

    await new Promise((resolve) => setTimeout(resolve, 30));
    await worker.close();

    expect(seen).toEqual(["run_b", "run_c"]);
    expect(redis.ackedCount).toBe(2);
  });

  it("recovers an entry a crashed consumer never acknowledged", async () => {
    const redis = new FakeRedis();
    const queue = createQueue(CONFIG, redis as unknown as Redis);
    await queue.add("run_d");

    // A consumer that claims the entry (via xreadgroup) and then hangs forever —
    // standing in for one that crashed mid-run and never reached xack.
    const crashed = startWorker(CONFIG, redis as unknown as Redis, () => new Promise(() => {}), {
      stallMs: 1,
    });
    await new Promise((resolve) => setTimeout(resolve, 10));
    // The entry is claimed but not yet acknowledged.
    expect(redis.ackedCount).toBe(0);

    // A fresh worker, with a near-zero stall window, reclaims it immediately via
    // xautoclaim rather than waiting for a new xreadgroup entry that never comes.
    const seen: string[] = [];
    const recovered = startWorker(
      CONFIG,
      redis as unknown as Redis,
      async (runId) => {
        seen.push(runId);
      },
      { stallMs: 1 },
    );

    await new Promise((resolve) => setTimeout(resolve, 20));
    await recovered.close();
    void crashed.close();

    expect(seen).toEqual(["run_d"]);
    expect(redis.ackedCount).toBe(1);
  });
});
