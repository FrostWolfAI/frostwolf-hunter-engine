import { describe, expect, it } from "vitest";
import { createGlinerJudge } from "../src/judge.js";

interface Call {
  url: string;
  headers: Record<string, string>;
  body: unknown;
}

/** A fetch that returns a fixed glidecide /v1/systemone body and records the request. */
function fakeFetch(body: unknown, ok = true): { fn: typeof fetch; calls: Call[] } {
  const calls: Call[] = [];
  const fn = (async (url: string | URL | Request, init?: RequestInit) => {
    calls.push({
      url: String(url),
      headers: (init?.headers ?? {}) as Record<string, string>,
      body: JSON.parse(String(init?.body ?? "{}")),
    });
    return new Response(JSON.stringify(body), { status: ok ? 200 : 500 });
  }) as typeof fetch;
  return { fn, calls };
}

const SUCCESS_BODY = { answers: { verdict: { type: "choice", choice: "success", confidence: 0.83 } } };

describe("createGlinerJudge", () => {
  it("maps a glidecide choice + confidence to a verdict", async () => {
    const { fn, calls } = fakeFetch(SUCCESS_BODY);
    const judge = createGlinerJudge("https://gli.test", {}, fn);
    const r = await judge("plausibility_judge", "decide", "evidence");
    expect(r.verdict.verdict).toBe("success");
    expect(r.verdict.confidence).toBeCloseTo(0.83);
    expect(r.verdict.next).toBe("verify");
    expect(r.verdict.gate).toBe("plausibility_judge");
    // Posts to /v1/systemone with the verdict choice question.
    expect(calls[0]!.url).toBe("https://gli.test/v1/systemone");
    expect((calls[0]!.body as { questions: { verdict: { type: string } } }).questions.verdict.type).toBe("choice");
  });

  it("sends no credential and no model to a bare decision service", async () => {
    const { fn, calls } = fakeFetch(SUCCESS_BODY);
    await createGlinerJudge("https://gli.test", {}, fn)("plausibility_judge", "i", "e");
    expect(calls[0]!.headers.authorization).toBeUndefined();
    expect(calls[0]!.body).not.toHaveProperty("model");
  });

  it("authenticates and names the model when reached through the gateway", async () => {
    const { fn, calls } = fakeFetch(SUCCESS_BODY);
    const judge = createGlinerJudge("https://gateway.test/v1", { apiKey: "key-1", model: "decide-1" }, fn);
    await judge("plausibility_judge", "i", "e");
    expect(calls[0]!.url).toBe("https://gateway.test/v1/systemone");
    expect(calls[0]!.headers.authorization).toBe("Bearer key-1");
    expect((calls[0]!.body as { model: string }).model).toBe("decide-1");
  });

  it("does not double the version segment when the base already ends in /v1/", async () => {
    const { fn, calls } = fakeFetch(SUCCESS_BODY);
    await createGlinerJudge("https://gateway.test/v1/", {}, fn)("plausibility_judge", "i", "e");
    expect(calls[0]!.url).toBe("https://gateway.test/v1/systemone");
  });

  it("fail-closes to inconclusive on an unknown choice", async () => {
    const { fn } = fakeFetch({ answers: { verdict: { choice: "maybe", confidence: 0.9 } } });
    const r = await createGlinerJudge("https://gli.test", {}, fn)("success_adjudicator", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
    expect(r.verdict.next).toBe("drop");
  });

  it("fail-closes on a non-200 response", async () => {
    const { fn } = fakeFetch({}, false);
    const r = await createGlinerJudge("https://gli.test", {}, fn)("verification_judge", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
  });

  it("fail-closes when the endpoint throws", async () => {
    const fn = (async () => { throw new Error("down"); }) as typeof fetch;
    const r = await createGlinerJudge("https://gli.test", {}, fn)("plausibility_judge", "i", "e");
    expect(r.verdict.verdict).toBe("inconclusive");
    expect(r.verdict.rationale).toContain("down");
  });
});
