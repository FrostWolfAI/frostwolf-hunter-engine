/**
 * The live run log, in memory.
 *
 * A hunt is started by a direct API call and runs in this same process, so the
 * live log lives here too: the runner `publish`es each line into a per-run buffer
 * and notifies any open SSE stream, and a late or reconnecting watcher replays the
 * buffer. The durable copy is written to D1 by the runner, so a finished run is
 * served from D1 (see `routes.ts`); this buffer only backs an in-progress run and
 * is dropped a short while after it ends. No Redis, no queue.
 */

import type { RunEvent, RunStatus } from "./types.js";

/** How often an idle stream is pinged so a proxy does not close it, in ms. */
const HEARTBEAT_MS = 15_000;
/** Cap on a single run's in-memory backlog, so a long run cannot grow without bound. */
const MAX_BUFFER = 5_000;
/** How long a finished run's buffer is kept for a late watcher before it is dropped. */
const FORGET_GRACE_MS = 2 * 60_000;

/** Where the runner publishes, and where the HTTP layer streams from. */
export interface Live {
  publish(runId: string, event: RunEvent): Promise<void>;
  end(runId: string, status: RunStatus): Promise<void>;
}

/** The in-memory live log plus its SSE stream, shared across the one process. */
export interface MemoryLive extends Live {
  stream(runId: string): ReadableStream<Uint8Array>;
}

type Subscriber = (frame: { event?: RunEvent; end?: RunStatus }) => void;

interface RunLog {
  readonly events: RunEvent[];
  ended: RunStatus | null;
  readonly subscribers: Set<Subscriber>;
}

export function createMemoryLive(): MemoryLive {
  const runs = new Map<string, RunLog>();
  const get = (runId: string): RunLog => {
    let log = runs.get(runId);
    if (log === undefined) {
      log = { events: [], ended: null, subscribers: new Set<Subscriber>() };
      runs.set(runId, log);
    }
    return log;
  };

  return {
    async publish(runId, event) {
      const log = get(runId);
      log.events.push(event);
      if (log.events.length > MAX_BUFFER) {
        log.events.shift();
      }
      for (const notify of log.subscribers) {
        notify({ event });
      }
    },

    async end(runId, status) {
      const log = get(runId);
      log.ended = status;
      for (const notify of log.subscribers) {
        notify({ end: status });
      }
      // The finished run is served from D1 from now on; drop the buffer after a
      // grace period so a watcher mid-reconnect still sees the final frames.
      const timer = setTimeout(() => runs.delete(runId), FORGET_GRACE_MS);
      timer.unref();
    },

    stream(runId) {
      const log = get(runId);
      const encoder = new TextEncoder();
      let heartbeat: ReturnType<typeof setInterval> | undefined;
      let subscriber: Subscriber | null = null;

      const cleanup = (): void => {
        if (heartbeat !== undefined) {
          clearInterval(heartbeat);
        }
        if (subscriber !== null) {
          log.subscribers.delete(subscriber);
          subscriber = null;
        }
      };

      return new ReadableStream<Uint8Array>({
        start(controller) {
          const write = (text: string): void => {
            try {
              controller.enqueue(encoder.encode(text));
            } catch {
              // The watcher is gone.
            }
          };

          write(": connected\n\n");
          for (const event of log.events) {
            write(`data: ${JSON.stringify(event)}\n\n`);
          }
          if (log.ended !== null) {
            controller.close();
            return;
          }

          subscriber = (frame) => {
            if (frame.event !== undefined) {
              write(`data: ${JSON.stringify(frame.event)}\n\n`);
            }
            if (frame.end !== undefined) {
              cleanup();
              try {
                controller.close();
              } catch {
                // Already closed.
              }
            }
          };
          log.subscribers.add(subscriber);
          heartbeat = setInterval(() => write(": ping\n\n"), HEARTBEAT_MS);
        },
        cancel: cleanup,
      });
    },
  };
}
