import { describe, expect, it } from "vitest";
import { runJudge } from "../src/judge.js";
import type { ModelClient } from "../src/models/types.js";

function clientReturning(content: string): ModelClient {
  return { async complete() { return { content, totalTokens: 7 }; } };
}

function throwingClient(message: string): ModelClient {
  return {
    async complete() {
      throw new Error(message);
    },
  };
}

const VALID = JSON.stringify({
  verdict: "success",
  confidence: 0.8,
  evidence_refs: ["a"],
  rationale: "clear and grounded",
  next: "verify",
});

describe("runJudge", () => {
  it("returns a well-formed verdict and its token count on a valid reply", async () => {
    const result = await runJudge(clientReturning(VALID), "m", "test_gate", "instructions", "evidence");
    expect(result.verdict).toEqual({
      gate: "test_gate",
      verdict: "success",
      confidence: 0.8,
      evidence_refs: ["a"],
      rationale: "clear and grounded",
      next: "verify",
    });
    expect(result.totalTokens).toBe(7);
  });

  it("clamps an out-of-range confidence into [0, 1]", async () => {
    const over = JSON.stringify({ ...JSON.parse(VALID), confidence: 4 });
    const under = JSON.stringify({ ...JSON.parse(VALID), confidence: -1 });
    expect((await runJudge(clientReturning(over), "m", "g", "i", "e")).verdict.confidence).toBe(1);
    expect((await runJudge(clientReturning(under), "m", "g", "i", "e")).verdict.confidence).toBe(0);
  });

  it("treats a call that throws as inconclusive and untrusted, not as failure", async () => {
    const result = await runJudge(throwingClient("network down"), "m", "g", "i", "e");
    expect(result.verdict.verdict).toBe("inconclusive");
    expect(result.verdict.next).toBe("drop");
    expect(result.verdict.rationale).toContain("network down");
    expect(result.totalTokens).toBeNull();
  });

  it("treats non-JSON content as inconclusive rather than throwing", async () => {
    const result = await runJudge(clientReturning("not json at all"), "m", "g", "i", "e");
    expect(result.verdict.verdict).toBe("inconclusive");
  });

  it("treats a reply missing required fields as inconclusive", async () => {
    const missingFields = JSON.stringify({ verdict: "success" });
    const result = await runJudge(clientReturning(missingFields), "m", "g", "i", "e");
    expect(result.verdict.verdict).toBe("inconclusive");
  });

  it("treats a reply with an out-of-enum verdict or next as inconclusive", async () => {
    const badVerdict = JSON.stringify({ ...JSON.parse(VALID), verdict: "definitely" });
    const badNext = JSON.stringify({ ...JSON.parse(VALID), next: "whatever" });
    expect((await runJudge(clientReturning(badVerdict), "m", "g", "i", "e")).verdict.verdict).toBe(
      "inconclusive",
    );
    expect((await runJudge(clientReturning(badNext), "m", "g", "i", "e")).verdict.verdict).toBe(
      "inconclusive",
    );
  });

  it("drops non-string entries from evidence_refs rather than failing the whole verdict", async () => {
    const mixed = JSON.stringify({ ...JSON.parse(VALID), evidence_refs: ["ok", 5, null] });
    const result = await runJudge(clientReturning(mixed), "m", "g", "i", "e");
    expect(result.verdict.evidence_refs).toEqual(["ok"]);
  });
});
