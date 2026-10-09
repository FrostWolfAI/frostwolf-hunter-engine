import { EventEmitter } from "node:events";
import type { Redis } from "ioredis";
import { describe, expect, it } from "vitest";
import { createLive, liveStream } from "../src/live.js";
import type { RunEvent } from "../src/types.js";

/** Just enough of Redis for the live log: lists, and pub/sub across duplicates. */
class FakeRedis extends EventEmitter {
  readonly lists = new Map<string, string[]>();
  private readonly subscribers = new Set<FakeRedis>();
  private channels = new Set<string>();
  /** Runs once, between a stream's subscribe and its backlog read. */
  beforeBacklog: (() => Promise<void>) | undefined;

  constructor(private readonly root: FakeRedis | null = null) {
    super();
  }

  duplicate(): FakeRedis {
    const copy = new FakeRedis(this.root ?? this);
    (this.root ?? this).subscribers.add(copy);
    return copy;
  }
  async subscribe(channel: string): Promise<void> {
    this.channels.add(channel);
  }
  async quit(): Promise<void> {
    (this.root ?? this).subscribers.delete(this);
  }
  async rpush(key: string, value: string): Promise<number> {
    const list = this.lists.get(key) ?? [];
    list.push(value);
    this.lists.set(key, list);
    return list.length;
  }
  async expire(): Promise<void> {}
  async publish(channel: string, message: string): Promise<void> {
    for (const subscriber of this.subscribers) {
      if (subscriber.channels.has(channel)) {
        subscriber.emit("message", channel, message);
      }
    }
  }
  async lrange(key: string): Promise<string[]> {
    await (this.root ?? this).beforeBacklog?.();
    return [...(this.lists.get(key) ?? [])];
  }
}

const event = (message: string): RunEvent => ({
  level: "info",
  stage: "recon",
  message,
  ts: "2026-10-04T00:00:00.000Z",
});

async function drain(stream: ReadableStream<Uint8Array>): Promise<string[]> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    text += decoder.decode(value);
  }
  return [...text.matchAll(/^data: (.*)$/gm)].map((m) => (JSON.parse(m[1]!) as RunEvent).message);
}

describe("live log", () => {
  it("replays the backlog, then streams live lines, then closes at the end", async () => {
    const redis = new FakeRedis();
    const live = createLive(redis as unknown as Redis);
    await live.publish("run_1", event("one"));
    await live.publish("run_1", event("two"));

    const stream = liveStream(redis as unknown as Redis, "run_1");
    const lines = drain(stream);
    await new Promise((resolve) => setTimeout(resolve, 10));
    await live.publish("run_1", event("three"));
    await live.end("run_1", "completed");

    expect(await lines).toEqual(["one", "two", "three"]);
  });

  it("neither drops nor repeats a line published during the replay", async () => {
    const redis = new FakeRedis();
    const live = createLive(redis as unknown as Redis);
    await live.publish("run_1", event("one"));

    // A line lands after the subscription opens but before the backlog is read,
    // so it is both in the list and in the held live messages.
    redis.beforeBacklog = async () => {
      redis.beforeBacklog = undefined;
      await live.publish("run_1", event("two"));
    };

    const lines = drain(liveStream(redis as unknown as Redis, "run_1"));
    await new Promise((resolve) => setTimeout(resolve, 10));
    await live.publish("run_1", event("three"));
    await live.end("run_1", "completed");

    expect(await lines).toEqual(["one", "two", "three"]);
  });

  it("keeps runs apart", async () => {
    const redis = new FakeRedis();
    const live = createLive(redis as unknown as Redis);
    await live.publish("run_a", event("a"));
    await live.publish("run_b", event("b"));
    await live.end("run_a", "completed");

    expect(await drain(liveStream(redis as unknown as Redis, "run_a"))).toEqual(["a"]);
  });
});
