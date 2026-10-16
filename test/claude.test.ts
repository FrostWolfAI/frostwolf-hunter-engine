import { describe, expect, it } from "vitest";
import { createClaudeExplorer, normalizeAnthropicBaseUrl } from "../src/claude.js";
import type { ExecFn } from "../src/orbcode.js";

function recordingClaudeExec(envelope: unknown, prefixLine = ""): {
  exec: ExecFn;
  calls: Array<{ args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv }>;
} {
  const calls: Array<{ args: readonly string[]; cwd: string; env: NodeJS.ProcessEnv }> = [];
  const exec: ExecFn = async (_bin, args, opts) => {
    calls.push({ args, cwd: opts.cwd, env: opts.env });
    const out = prefixLine
      ? `${prefixLine}\n${JSON.stringify(envelope)}\n`
      : `${JSON.stringify(envelope)}\n`;
    return { stdout: out, stderr: "", code: 0 };
  };
  return { exec, calls };
}

const base = {
  bin: "/usr/local/bin/claude",
  baseUrl: "https://api2.matterai.so/v1",
  apiKey: "fw-secret-key",
  timeoutMs: 5000,
} as const;

describe("createClaudeExplorer", () => {
  it("normalizes OpenAI-style /v1 base URLs for ANTHROPIC_BASE_URL", () => {
    expect(normalizeAnthropicBaseUrl("https://api2.matterai.so/v1")).toBe("https://api2.matterai.so");
    expect(normalizeAnthropicBaseUrl("https://api2.matterai.so/v1/")).toBe("https://api2.matterai.so");
    expect(normalizeAnthropicBaseUrl("https://api2.matterai.so")).toBe("https://api2.matterai.so");
  });

  it("overrides base URL, model, and API key, enables dangerous permissions, and disables parallel agents", async () => {
    const { exec, calls } = recordingClaudeExec(
      {
        type: "result",
        subtype: "success",
        is_error: false,
        session_id: "sess-claude-1",
        result: '{"hypotheses":[]}',
        usage: { input_tokens: 200, output_tokens: 80 },
        modelUsage: {
          "frost-abliterated-cyber-max-1": {
            inputTokens: 200,
            outputTokens: 80,
          },
        },
      },
      '[claude-code:unrecognized_model] {"model":"frost-abliterated-cyber-max-1"}',
    );

    let charged = 0;
    const explore = createClaudeExplorer(
      base,
      "/repo",
      () => {},
      (t) => (charged += t),
      exec,
    );

    const result = await explore<{ hypotheses: unknown[] }>({
      model: "frost-abliterated-cyber-max-1",
      system: "system prompt",
      task: "task prompt",
      stage: "synthesis",
    });

    expect(result).toEqual({ hypotheses: [] });
    expect(charged).toBe(280);

    const call = calls[0]!;
    expect(call.cwd).toBe("/repo");
    expect(call.args).toContain("--bare");
    expect(call.args).toContain("--output-format");
    expect(call.args).toContain("json");
    expect(call.args).toContain("--model");
    expect(call.args).toContain("frost-abliterated-cyber-max-1");
    expect(call.args).toContain("--dangerously-skip-permissions");
    expect(call.args).toContain("--disallowedTools");
    expect(call.args).toContain("Agent,Task,TeamCreate,SendMessage");

    // Verify env overrides
    expect(call.env.ANTHROPIC_BASE_URL).toBe("https://api2.matterai.so");
    expect(call.env.ANTHROPIC_API_KEY).toBe("fw-secret-key");
    expect(call.env.ANTHROPIC_AUTH_TOKEN).toBe("fw-secret-key");
    expect(call.env.ANTHROPIC_MODEL).toBe("frost-abliterated-cyber-max-1");
    expect(call.env.ANTHROPIC_DEFAULT_SONNET_MODEL).toBe("frost-abliterated-cyber-max-1");
    expect(call.env.ANTHROPIC_DEFAULT_OPUS_MODEL).toBe("frost-abliterated-cyber-max-1");
    expect(call.env.ANTHROPIC_DEFAULT_HAIKU_MODEL).toBe("frost-abliterated-cyber-max-1");
    expect(call.env.CLAUDE_CODE_DISABLE_SUBAGENTS).toBe("1");
    expect(call.env.CLAUDE_CODE_DISABLE_BACKGROUND_TASKS).toBe("1");
    expect(call.env.NODE_OPTIONS).toBe("");
  });

  it("reuses one session across non-fresh calls and starts fresh for verification", async () => {
    const { exec, calls } = recordingClaudeExec({
      type: "result",
      is_error: false,
      session_id: "sess-claude-shared",
      result: "{}",
    });
    const explore = createClaudeExplorer(base, "/repo", () => {}, () => {}, exec);

    const resumeArg = (i: number) => {
      const a = calls[i]!.args;
      const at = a.indexOf("--resume");
      return at === -1 ? null : a[at + 1];
    };

    await explore({ model: "m1", system: "s", task: "t", stage: "recon" });
    expect(resumeArg(0)).toBeNull();

    await explore({ model: "m1", system: "s", task: "t", stage: "synthesis" });
    expect(resumeArg(1)).toBe("sess-claude-shared");

    await explore({ model: "m2", system: "s", task: "t", stage: "verify", fresh: true });
    expect(resumeArg(2)).toBeNull();

    await explore({ model: "m1", system: "s", task: "t", stage: "exploit" });
    expect(resumeArg(3)).toBe("sess-claude-shared");
  });

  it("discards output if modelUsage reports a different model than requested", async () => {
    const { exec } = recordingClaudeExec({
      type: "result",
      is_error: false,
      result: '{"ok":true}',
      modelUsage: { "wrong-fallback-model": { inputTokens: 10, outputTokens: 10 } },
    });
    const warnings: string[] = [];
    const explore = createClaudeExplorer(
      base,
      "/repo",
      (_l, _s, m) => warnings.push(m),
      () => {},
      exec,
    );
    const result = await explore({ model: "expected-model", system: "s", task: "t", stage: "recon" });
    expect(result).toBeNull();
    expect(warnings.join(" ")).toMatch(/ran "wrong-fallback-model", not "expected-model"/);
  });

  it("returns null when claude reports is_error=true", async () => {
    const { exec } = recordingClaudeExec({
      type: "result",
      is_error: true,
      result: "API Error: 500",
    });
    const explore = createClaudeExplorer(base, "/repo", () => {}, () => {}, exec);
    expect(await explore({ model: "m1", system: "s", task: "t", stage: "recon" })).toBeNull();
  });
});
