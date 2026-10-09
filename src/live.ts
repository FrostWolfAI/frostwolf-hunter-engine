/**
 * The live run log, in Redis.
 *
 * Each line is appended to a per-run list (so a watcher who connects late can
 * replay it) and published on a per-run channel (so a connected watcher gets it as
 * it happens). The list expires; the durable copy is written to D1 in batches by
 * the runner. This keeps the high-volume live chatter off the database.
 */

import type { Redis } from "ioredis";
import type { RunEvent, RunStatus } from "./types.js";

/** How long a run's live log is kept in Redis after its last line, in seconds. */
const LOG_TTL_SECONDS = 24 * 60 * 60;

/** How often an idle stream is pinged so a proxy does not close it, in ms. */
const HEARTBEAT_MS = 15_000;

/** Where the runner publishes. */
export interface Live {
  publish(runId: string, event: RunEvent): Promise<void>;
  end(runId: string, status: RunStatus): Promise<void>;
}

const logKey = (runId: string): string => `hunter:run:${runId}:log`;
const channel = (runId: string): string => `hunter:run:${runId}`;

export function createLive(redis: Redis): Live {
  return {
    async publish(runId, event) {
      const length = await redis.rpush(logKey(runId), JSON.stringify(event));
      await redis.expire(logKey(runId), LOG_TTL_SECONDS);
      await redis.publish(channel(runId), JSON.stringify({ n: length, event }));
    },
    async end(runId, status) {
      // Recorded in the log as well as published, so a watcher who connects after
      // the run has finished still sees that it is over instead of waiting.
      const frame = JSON.stringify({ end: true, status });
      await redis.rpush(logKey(runId), frame);
      await redis.expire(logKey(runId), LOG_TTL_SECONDS);
      await redis.publish(channel(runId), frame);
    },
  };
}

interface Frame {
  readonly n?: number;
  readonly event?: RunEvent;
  readonly end?: boolean;
}

/**
 * A server-sent-event stream of a run's log: the backlog first, then live lines.
 *
 * The subscription is opened before the backlog is read, and live lines that
 * arrive during the replay are held and de-duplicated by their position in the
 * list, so a line is never dropped or sent twice. The stream closes when the run
 * ends or the watcher goes away.
 */
export function liveStream(redis: Redis, runId: string): ReadableStream<Uint8Array> {
  const subscriber = redis.duplicate();
  const encoder = new TextEncoder();
  let heartbeat: ReturnType<typeof setInterval> | undefined;

  const cleanup = (): void => {
    clearInterval(heartbeat);
    subscriber.quit().catch(() => undefined);
  };

  return new ReadableStream<Uint8Array>({
    async start(controller) {
      const write = (text: string): void => {
        try {
          controller.enqueue(encoder.encode(text));
        } catch {
          // The watcher is gone.
        }
      };

      let replaying = true;
      let sent = 0;
      let ended = false;
      const held: Frame[] = [];

      const deliver = (frame: Frame): void => {
        if (frame.end === true) {
          ended = true;
          return;
        }
        if (frame.event !== undefined && (frame.n ?? 0) > sent) {
          sent = frame.n ?? sent;
          write(`data: ${JSON.stringify(frame.event)}\n\n`);
        }
      };

      subscriber.on("message", (_channel, raw) => {
        const frame = JSON.parse(raw) as Frame;
        if (replaying) {
          held.push(frame);
        } else {
          deliver(frame);
          if (ended) {
            cleanup();
            controller.close();
          }
        }
      });

      await subscriber.subscribe(channel(runId));
      write(": connected\n\n");

      const backlog = await redis.lrange(logKey(runId), 0, -1);
      backlog.forEach((raw, index) => {
        if ((JSON.parse(raw) as Frame).end === true) {
          ended = true;
          return;
        }
        sent = index + 1;
        write(`data: ${raw}\n\n`);
      });

      replaying = false;
      held.forEach(deliver);

      if (ended) {
        cleanup();
        controller.close();
        return;
      }
      heartbeat = setInterval(() => write(": ping\n\n"), HEARTBEAT_MS);
    },
    cancel: cleanup,
  });
}
