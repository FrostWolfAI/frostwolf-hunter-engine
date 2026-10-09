import { describe, expect, it } from "vitest";
import { createGlinerJudge } from "../src/judge.js";

/** A fetch that returns a fixed glidecide /v1/systemone body and records the request. */
function fakeFetch(body: unknown, ok = true): { fn: typeof fetch; calls: Array<{ url: string; body: unknown }> } {
  const calls: Array<{ url: string; body: unknown }> = [];
  const fn = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({ url: String(url), body: JSON.parse(String(init?.body ?? "{}")) });
    return new Response(JSON.stringify(body), { status: ok ? 200 : 500 });
  }) as typeof fetch;
  return { fn, calls };
}

describe("createGlinerJudge", () => {
  it("maps a glidecide choice + confidence to a verdict", async () => {
    const { fn, calls } = fakeFetch({ answers: { verdict: { type: "choice", choice: "success", confidence: 0.83 } } });
    const judge = createGlinerJudge("https://gli.test", fn);
    const r = await judge("plausibility_judge", "decide", "evidence");
    expect(r.verdict.verdict).toBe("success");
    expect(r.verdict.confidence).toBeCloseTo(0.83);
    expect(r.verdict.next).toBe("verify");
    expect(r.verdict.gate).toBe("plausibility_judge");
    // Posts to /v1/systemone with the verdict choice question.
    expect(calls[0]!.url).toBe("https://gli.test/v1/systemone");
    expect((calls[0]!.body as { questions: { verdict: { type: string } } }).questions.verdict.type).toBe("choice");
  });

  it("fail-closes to inconclusive on an unknown choice", async () => {
    const { fn } = fakeFetch({ answers: { verdict: { choice: "maybe", confidence: 0.9 } } });
    const r = await createGlinerJudge("https://gli.test", fn)("success_adjudicator", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
    expect(r.verdict.next).toBe("drop");
  });

  it("fail-closes on a non-200 response", async () => {
    const { fn } = fakeFetch({}, false);
    const r = await createGlinerJudge("https://gli.test", fn)("verification_judge", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
  });

  it("fail-closes when the endpoint throws", async () => {
    const fn = (async () => { throw new Error("down"); }) as typeof fetch;
    const r = await createGlinerJudge("https://gli.test", fn)("plausibility_judge", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
    expect(r.verdict.rationale).toContain("down");
  });
});
