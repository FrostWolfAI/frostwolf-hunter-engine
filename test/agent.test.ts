import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runAgent } from "../src/agent.js";
import type { CompletionOptions, ModelClient } from "../src/models/types.js";
import type { RunContext } from "../src/state-machine.js";
import { RepoTools, buildToolset, type BrokeredTool } from "../src/tools.js";

/** A fixture repo with a searchable marker. */
const dir = mkdtempSync(join(tmpdir(), "hunter-agent-"));
mkdirSync(join(dir, "src"), { recursive: true });
writeFileSync(join(dir, "src", "auth.js"), "const userId = req.query.userId; // TAINT\n");
afterAll(() => rmSync(dir, { recursive: true, force: true }));

/** A ModelClient that replays a fixed script of replies, recording what it saw. */
function scriptClient(replies: string[]): { client: ModelClient; calls: CompletionOptions[] } {
  const calls: CompletionOptions[] = [];
  let i = 0;
  const client: ModelClient = {
    async complete(options) {
      calls.push(options);
      const content = replies[Math.min(i, replies.length - 1)]!;
      i += 1;
      return { content, totalTokens: 10 };
    },
  };
  return { client, calls };
}

/** Build a minimal RunContext around a client and a toolset. */
function makeCtx(
  client: ModelClient,
  brokered: { bash?: BrokeredTool; webSearch?: BrokeredTool } = {},
): { ctx: RunContext; events: string[]; tokens: () => number } {
  const events: string[] = [];
  let used = 0;
  const tools = buildToolset(new RepoTools(dir), brokered);
  const ctx = {
    client,
    tools,
    budget: { add: (n: number) => (used += n), exceeded: () => used >= 1000 },
    models: { costPer1kTokensUsd: 0.001 },
    emit: (_l: string, _s: string, m: string) => events.push(m),
    spend: () => {},
  } as unknown as RunContext;
  return { ctx, events, tokens: () => used };
}

describe("runAgent", () => {
  it("uses a tool, feeds the observation back, then returns the final result", async () => {
    const { client, calls } = scriptClient([
      JSON.stringify({ actions: [{ tool: "search", args: { query: "TAINT" } }] }),
      JSON.stringify({ done: true, result: { ok: true } }),
    ]);
    const { ctx } = makeCtx(client);

    const result = await runAgent<{ ok: boolean }>(ctx, {
      model: "m",
      stage: "recon",
      maxSteps: 5,
      system: "test",
      task: "find the taint",
    });

    expect(result).toEqual({ ok: true });
    // The second call's transcript must contain the tool observation (the match).
    const secondPrompt = JSON.stringify(calls[1]!.messages);
    expect(secondPrompt).toContain("src/auth.js:1");
    expect(secondPrompt).toContain("TAINT");
  });

  it("returns null when the model never finishes within maxSteps", async () => {
    // Always asks for another tool call, never says done.
    const { client } = scriptClient([
      JSON.stringify({ actions: [{ tool: "list_dir", args: { path: "" } }] }),
    ]);
    const { ctx } = makeCtx(client);

    const result = await runAgent(ctx, {
      model: "m",
      stage: "recon",
      maxSteps: 3,
      system: "test",
      task: "loop",
    });
    expect(result).toBeNull();
  });

  it("can drive a brokered bash tool and receive its output", async () => {
    const { client, calls } = scriptClient([
      JSON.stringify({ actions: [{ tool: "bash", args: { cmd: "node -v" } }] }),
      JSON.stringify({ done: true, result: "done" }),
    ]);
    let ranCmd = "";
    const bash: BrokeredTool = async (args) => {
      ranCmd = String(args.cmd);
      return "v22.0.0";
    };
    const { ctx } = makeCtx(client, { bash });

    const result = await runAgent<string>(ctx, {
      model: "m",
      stage: "synthesis",
      maxSteps: 5,
      system: "test",
      task: "check the runtime",
    });

    expect(result).toBe("done");
    expect(ranCmd).toBe("node -v");
    expect(JSON.stringify(calls[1]!.messages)).toContain("v22.0.0");
  });

  it("does not offer bash when no broker is available", async () => {
    const { client } = scriptClient([JSON.stringify({ done: true, result: null })]);
    const { ctx } = makeCtx(client);
    // The toolset docs the agent is shown must not advertise bash.
    expect(ctx.tools.docs).not.toContain("bash(");
    const result = await runAgent(ctx, {
      model: "m",
      stage: "recon",
      maxSteps: 2,
      system: "test",
      task: "noop",
    });
    expect(result).toBeNull();
  });
});
