/**
 * The sandboxed child process: one per run.
 *
 * It is started with an empty environment and Node's `--permission` model, so it
 * holds no ambient secret, cannot write files, and cannot spawn processes. It takes
 * the run over IPC, reasons, and reports back over IPC. The privileged tools it
 * cannot run itself — `bash` (container) and `web_search` (search key) — it brokers
 * to the parent: it posts a `tool_request` and awaits the matching `tool_response`.
 * So the key and the ability to execute stay in the parent; the child only asks.
 */

import { randomUUID } from "node:crypto";
import { executeRun, type ToolBroker } from "./pipeline.js";
import type { ChildMessage, ParentMessage, RunInput } from "./types.js";

/** How long the child waits for a brokered tool before giving up on that call. */
const TOOL_TIMEOUT_MS = 180_000;

function send(message: ChildMessage): void {
  if (message.type === "done") {
    process.send?.(message, undefined, undefined, () => process.exit(message.ok ? 0 : 1));
    return;
  }
  process.send?.(message);
}

const pending = new Map<string, (result: string) => void>();

const broker: ToolBroker = (tool, args) =>
  new Promise((resolve) => {
    const id = randomUUID();
    const timer = setTimeout(() => {
      if (pending.delete(id)) {
        resolve(`error: ${tool} timed out`);
      }
    }, TOOL_TIMEOUT_MS);
    pending.set(id, (result) => {
      clearTimeout(timer);
      resolve(result);
    });
    send({ type: "tool_request", id, tool, args });
  });

let started = false;
process.on("message", (message: RunInput | ParentMessage) => {
  if ((message as ParentMessage).type === "tool_response") {
    const response = message as ParentMessage;
    const resolve = pending.get(response.id);
    if (resolve !== undefined) {
      pending.delete(response.id);
      resolve(response.result);
    }
    return;
  }
  if (started) {
    return;
  }
  started = true;
  executeRun(message as RunInput, send, { broker }).catch((error: unknown) => {
    send({
      type: "done",
      ok: false,
      reason: error instanceof Error ? error.message : "run crashed",
    });
  });
});
