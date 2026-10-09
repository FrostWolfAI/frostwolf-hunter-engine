import { describe, expect, it } from "vitest";
import { createOrbcodeExplorer, type ExecFn } from "../src/orbcode.js";

/** A fake exec that returns a fixed orbcode `--json` envelope and records args. */
function recordingExec(envelope: unknown): {
  exec: ExecFn;
  calls: Array<{ args: readonly string[]; cwd: string }>;
} {
  const calls: Array<{ args: readonly string[]; cwd: string }> = [];
  const exec: ExecFn = async (_bin, args, opts) => {
    calls.push({ args, cwd: opts.cwd });
    return { stdout: `${JSON.stringify(envelope)}\n`, stderr: "", code: 0 };
  };
  return { exec, calls };
}

const base = {
  bin: "/orb/bin.js",
  baseUrl: "https://ep/v1",
  apiKey: "none",
  models: ["m1", "m2"],
  execute: false,
  timeoutMs: 1000,
} as const;

describe("createOrbcodeExplorer", () => {
  it("drives orbcode in structured read-only mode and parses the result", async () => {
    const { exec, calls } = recordingExec({
      ok: true,
      model: "m1",
      result: '{"hypotheses":[]}',
      usage: { inputTokens: 100, outputTokens: 50 },
    });
    let charged = 0;
    const explore = createOrbcodeExplorer(base, "/repo", () => {}, (t) => (charged += t), exec);

    const result = await explore<{ hypotheses: unknown[] }>({
      model: "m1", system: "s", task: "t", stage: "synthesis",
    });

    expect(result).toEqual({ hypotheses: [] });
    expect(charged).toBe(150); // usage fed to the cost governor
    const args = calls[0]!.args;
    expect(args).toContain("--json");
    expect(args).toContain("--require-model");
    expect(args).toContain("--output-file");
    expect(args).toContain("--model");
    expect(args).toContain("m1");
    expect(args).not.toContain("--yolo"); // read-only
    expect(calls[0]!.cwd).toBe("/repo");
  });

  it("adds --yolo only in execute mode", async () => {
    const { exec, calls } = recordingExec({ ok: true, model: "m1", result: "{}" });
    const explore = createOrbcodeExplorer({ ...base, execute: true, models: ["m1"] }, "/repo", () => {}, () => {}, exec);
    await explore({ model: "m1", system: "s", task: "t", stage: "exploit" });
    expect(calls[0]!.args).toContain("--yolo");
  });

  it("discards output from a model other than the one requested", async () => {
    const { exec } = recordingExec({ ok: true, model: "some-default", result: '{"x":1}' });
    const warnings: string[] = [];
    const explore = createOrbcodeExplorer(base, "/repo", (_l, _s, m) => warnings.push(m), () => {}, exec);
    const result = await explore({ model: "m1", system: "s", task: "t", stage: "recon" });
    expect(result).toBeNull();
    expect(warnings.join(" ")).toMatch(/ran "some-default", not "m1"/);
  });

  it("returns null when orbcode reports an error", async () => {
    const { exec } = recordingExec({ ok: false, model: "m1", result: "", error: "model unavailable" });
    const explore = createOrbcodeExplorer(base, "/repo", () => {}, () => {}, exec);
    expect(await explore({ model: "m1", system: "s", task: "t", stage: "recon" })).toBeNull();
  });

  it("returns null when the result is not usable JSON", async () => {
    const { exec } = recordingExec({ ok: true, model: "m1", result: "I could not complete the task." });
    const explore = createOrbcodeExplorer(base, "/repo", () => {}, () => {}, exec);
    expect(await explore({ model: "m1", system: "s", task: "t", stage: "recon" })).toBeNull();
  });

  it("returns null when stdout is not a JSON envelope at all", async () => {
    const exec: ExecFn = async () => ({ stdout: "boom\n", stderr: "", code: 1 });
    const explore = createOrbcodeExplorer(base, "/repo", () => {}, () => {}, exec);
    expect(await explore({ model: "m1", system: "s", task: "t", stage: "recon" })).toBeNull();
  });
});
