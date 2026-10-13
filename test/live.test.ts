import { describe, expect, it } from "vitest";
import { createMemoryLive } from "../src/live.js";
import type { RunEvent } from "../src/types.js";

function evt(message: string): RunEvent {
  return { level: "info", stage: "recon", message, ts: new Date().toISOString() };
}

/** Read an SSE stream to completion, returning the `message` of each data frame. */
async function drain(stream: ReadableStream<Uint8Array>): Promise<string[]> {
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  const messages: string[] = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) {
      break;
    }
    buffer += decoder.decode(value, { stream: true });
    let nl: number;
    while ((nl = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, nl);
      buffer = buffer.slice(nl + 2);
      const dataLine = frame.split("\n").find((line) => line.startsWith("data:"));
      if (dataLine !== undefined) {
        messages.push((JSON.parse(dataLine.slice(5).trim()) as RunEvent).message);
      }
    }
  }
  return messages;
}

describe("in-memory live log", () => {
  it("replays the backlog, then streams live lines, then closes at the end", async () => {
    const live = createMemoryLive();
    await live.publish("run_1", evt("a"));
    await live.publish("run_1", evt("b"));
    const streamed = drain(live.stream("run_1")); // subscribes, replays a + b
    await live.publish("run_1", evt("c"));
    await live.end("run_1", "completed");
    expect(await streamed).toEqual(["a", "b", "c"]);
  });

  it("serves a late watcher the full backlog and closes when the run already ended", async () => {
    const live = createMemoryLive();
    await live.publish("run_1", evt("x"));
    await live.publish("run_1", evt("y"));
    await live.end("run_1", "completed");
    expect(await drain(live.stream("run_1"))).toEqual(["x", "y"]);
  });

  it("keeps runs apart", async () => {
    const live = createMemoryLive();
    await live.publish("run_a", evt("a"));
    await live.publish("run_b", evt("b"));
    await live.end("run_a", "completed");
    await live.end("run_b", "completed");
    expect(await drain(live.stream("run_a"))).toEqual(["a"]);
    expect(await drain(live.stream("run_b"))).toEqual(["b"]);
  });
});
