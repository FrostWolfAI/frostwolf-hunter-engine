/**
 * The agent loop — the model drives, with tools, until it has an answer.
 *
 * This is what makes recon and synthesis a real scan rather than a one-shot look:
 * the model lists directories, reads files, searches for a symbol across the repo,
 * runs a command in the sandbox, follows a data flow, and only then answers. Each
 * turn it returns JSON that is either a batch of tool calls to run, or the final
 * result. We execute the tools, feed the observations back, and loop.
 *
 * It is bounded on every axis a runaway could escape on — steps, wall-clock, and
 * tokens (the shared per-run budget) — so the loop always terminates and the cost
 * governor can stop a hunt that is spending without converging. When the budget is
 * hit it makes one last "answer now with what you have" call rather than cutting off
 * mid-thought, and if even that fails it returns null and the stage degrades.
 */

import type { ChatMessage, ModelClient } from "./models/types.js";
import type { RunContext } from "./state-machine.js";
import { parseLooseJson } from "./json.js";
import { parseToolCalls, truncate } from "./tools.js";

export interface AgentOptions {
  readonly model: string;
  /** The role + output-contract instructions. The tool docs are appended for you. */
  readonly system: string;
  /** The task and any starting context. */
  readonly task: string;
  /** Max tool-calling rounds before the agent must answer. */
  readonly maxSteps: number;
  /** Stage name for log lines. */
  readonly stage: string;
  readonly temperature?: number;
}

/** How many tool calls we honour in a single turn, so one turn can't fan out forever. */
const MAX_ACTIONS_PER_TURN = 6;

interface AgentReply {
  readonly actions?: unknown;
  readonly done?: boolean;
  readonly result?: unknown;
}

/**
 * Run the loop and return the model's final `result`, or null if it never produced
 * a usable one within budget.
 */
export async function runAgent<T>(ctx: RunContext, options: AgentOptions): Promise<T | null> {
  const client: ModelClient = ctx.client;
  const toolset = ctx.tools;
  const messages: ChatMessage[] = [
    {
      role: "system",
      content:
        `${options.system}\n\n${toolset.docs}\n\n` +
        "Work in steps. Each reply MUST be one JSON object, either\n" +
        '  {"actions": [{"tool": name, "args": {...}}, ...]}  to use tools, or\n' +
        '  {"done": true, "result": <your final answer>}  when you are ready.\n' +
        "Prefer a few targeted tool calls over guessing. Do not answer until you have " +
        "read the relevant code.",
    },
    { role: "user" as const, content: options.task },
  ];

  for (let step = 0; step < options.maxSteps; step++) {
    const lastChance = step === options.maxSteps - 1 || ctx.budget.exceeded();
    if (lastChance) {
      messages.push({
        role: "user" as const,
        content: 'Budget reached. Reply now with {"done": true, "result": ...} using only what you have.',
      });
    }

    let reply: AgentReply | null;
    try {
      const completion = await client.complete({
        model: options.model,
        temperature: options.temperature ?? 0.4,
        json: true,
        messages,
      });
      account(ctx, completion.totalTokens);
      reply = parseLooseJson(completion.content) as AgentReply | null;
      if (reply === null || typeof reply !== "object") {
        throw new Error("not a JSON object");
      }
    } catch (error) {
      ctx.emit("warn", options.stage, `agent reply unusable: ${errText(error)}`);
      messages.push({
        role: "user" as const,
        content: 'Your last reply was not valid JSON. Reply with {"actions": [...]} or {"done": true, "result": ...}.',
      });
      continue;
    }

    if (reply.done === true || reply.result !== undefined) {
      return (reply.result ?? null) as T | null;
    }
    if (lastChance) {
      return null;
    }

    const calls = parseToolCalls(reply.actions).slice(0, MAX_ACTIONS_PER_TURN);
    if (calls.length === 0) {
      messages.push({
        role: "user" as const,
        content: 'No actions found. Reply with {"actions": [...]} or {"done": true, "result": ...}.',
      });
      continue;
    }

    const observations: string[] = [];
    for (const call of calls) {
      const result = await toolset.run(call);
      ctx.emit("debug", options.stage, `${call.tool}(${JSON.stringify(call.args).slice(0, 120)})`);
      observations.push(`$ ${call.tool} ${JSON.stringify(call.args)}\n${result}`);
    }
    // Echo the model's own action list back, then the observations, so the next
    // turn has the full trail of what it did and saw.
    messages.push({ role: "assistant" as const, content: JSON.stringify({ actions: calls }) });
    messages.push({ role: "user" as const, content: truncate(observations.join("\n\n"), 12000) });
  }

  return null;
}

/** Charge a call's tokens to the run — both the dollar meter and the budget guard. */
export function account(ctx: RunContext, totalTokens: number | null): void {
  if (totalTokens !== null) {
    ctx.spend((totalTokens / 1000) * ctx.models.costPer1kTokensUsd);
    ctx.budget.add(totalTokens);
  }
}

function errText(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}
