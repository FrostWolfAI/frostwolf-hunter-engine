/**
 * The run queue, as a native Redis stream — no queueing library.
 *
 * A Redis stream with a consumer group gives the two properties a job queue
 * needs without adding a dependency: `XREADGROUP` hands each entry to exactly
 * one consumer, and an entry that is never acknowledged (because its consumer
 * crashed mid-run) is recovered by `XAUTOCLAIM` once it has sat unacknowledged
 * past `STALL_MS`, so a crash loses at most the one run a worker was holding,
 * not the queue.
 *
 * Enqueueing the same run twice is a no-op, guarded by a short-lived Redis key
 * rather than a queue-level job id — streams have no job-id dedup the way a
 * queueing library does, so the guard is explicit here.
 */

import type { Redis } from "ioredis";
import type { Config } from "./config.js";

const GROUP = "hunter-workers";

/** How long a claimed entry may go unacknowledged before another consumer may steal it. */
const STALL_MS = 60_000;
/** How long the enqueue dedup guard lives, in seconds. */
const DEDUP_TTL_SECONDS = 3600;
/** How long one blocking read waits for a new entry before looping again. */
const BLOCK_MS = 5_000;

export interface RunQueue {
  add(runId: string): Promise<void>;
  close(): Promise<void>;
}

export function createQueue(config: Config, redis: Redis): RunQueue {
  return {
    async add(runId) {
      const added = await redis.set(`hunter:enqueued:${runId}`, "1", "EX", DEDUP_TTL_SECONDS, "NX");
      if (added === null) {
        return; // Already enqueued; a no-op, not an error.
      }
      await redis.xadd(config.queueName, "*", "run_id", runId);
    },
    async close() {
      // The connection is owned by the caller (index.ts); nothing of this
      // queue's own needs releasing.
    },
  };
}

/** Create the consumer group if it does not exist yet. Idempotent. */
async function ensureGroup(redis: Redis, stream: string): Promise<void> {
  try {
    await redis.xgroup("CREATE", stream, GROUP, "$", "MKSTREAM");
  } catch (error) {
    if (!/BUSYGROUP/.test(String(error))) {
      throw error;
    }
  }
}

/** One stream entry's fields, flattened from Redis's [field, value, ...] array. */
type Fields = readonly string[];

function runIdOf(fields: Fields): string | null {
  const index = fields.indexOf("run_id");
  return index === -1 ? null : (fields[index + 1] ?? null);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A worker pool: `config.concurrency` parallel consumer loops on one stream. */
export interface QueueWorker {
  close(): Promise<void>;
}

export function startWorker(
  config: Config,
  redis: Redis,
  handler: (runId: string) => Promise<unknown>,
  options: { stallMs?: number } = {},
): QueueWorker {
  const stallMs = options.stallMs ?? STALL_MS;
  let stopped = false;

  const handleEntry = async (entryId: string, fields: Fields): Promise<void> => {
    const runId = runIdOf(fields);
    if (runId !== null) {
      try {
        await handler(runId);
      } catch {
        // The handler (processRun) catches its own failures and always
        // resolves; reaching here means something outside that contract broke.
        // It is still acknowledged below — a run that throws from the runner
        // is a bug to fix, not one to retry forever.
      }
    }
    await redis.xack(config.queueName, GROUP, entryId).catch(() => undefined);
  };

  const loop = async (consumer: string): Promise<void> => {
    await ensureGroup(redis, config.queueName);

    while (!stopped) {
      // Recover anything a crashed consumer left claimed-but-unacknowledged
      // before waiting for new work, so a stall is bounded by this loop's own
      // cadence rather than by a separate sweep process.
      try {
        const claimed = (await redis.xautoclaim(
          config.queueName,
          GROUP,
          consumer,
          stallMs,
          "0-0",
          "COUNT",
          1,
        )) as [string, Array<[string, Fields]>, string[]];
        for (const [entryId, fields] of claimed[1]) {
          await handleEntry(entryId, fields);
        }
      } catch {
        // A transient Redis error here is not fatal; the next iteration retries.
      }

      if (stopped) {
        break;
      }

      let batch: Array<[string, Array<[string, Fields]>]> | null = null;
      try {
        batch = (await redis.xreadgroup(
          "GROUP",
          GROUP,
          consumer,
          "COUNT",
          1,
          "BLOCK",
          BLOCK_MS,
          "STREAMS",
          config.queueName,
          ">",
        )) as [string, Array<[string, Fields]>][] | null;
      } catch {
        // Likely a disconnect; back off before the next attempt rather than
        // spinning hot against a Redis that is still coming back up.
        await sleep(BLOCK_MS);
      }

      for (const [, entries] of batch ?? []) {
        for (const [entryId, fields] of entries) {
          await handleEntry(entryId, fields);
        }
      }
    }
  };

  const loops = Array.from({ length: config.concurrency }, (_, i) =>
    loop(`engine-${process.pid}-${i}`),
  );

  return {
    async close() {
      stopped = true;
      await Promise.all(loops);
    },
  };
}
