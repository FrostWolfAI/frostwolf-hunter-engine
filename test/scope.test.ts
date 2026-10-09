import { describe, expect, it } from "vitest";
import { isInScope, scopedFetch, scopeHosts, scopeRepo } from "../src/scope.js";
import type { RunJob } from "../src/types.js";

const JOB: RunJob = {
  run_id: "r",
  hunt_id: "h",
  tenant_id: "t",
  provider: "github",
  repos: [],
  repoUrl: null,
  scope: { hosts: ["app.acme.test", "api.acme.test"] },
  depth: "standard",
  policy: {},
};

describe("scopeRepo", () => {
  it("reads a declared repository URL, or null", () => {
    expect(scopeRepo({ ...JOB, scope: { repo: "https://github.com/a/b" } })).toBe(
      "https://github.com/a/b",
    );
    expect(scopeRepo(JOB)).toBeNull();
    expect(scopeRepo({ ...JOB, scope: { repo: 5 } })).toBeNull();
  });
});

describe("scopeHosts", () => {
  it("reads the declared hosts", () => {
    expect(scopeHosts(JOB)).toEqual(["app.acme.test", "api.acme.test"]);
  });

  it("is empty for a missing or malformed scope", () => {
    expect(scopeHosts({ ...JOB, scope: {} })).toEqual([]);
    expect(scopeHosts({ ...JOB, scope: { hosts: "not-an-array" } })).toEqual([]);
    expect(scopeHosts({ ...JOB, scope: { hosts: ["ok", 5, null] } })).toEqual(["ok"]);
  });
});

describe("isInScope", () => {
  const hosts = ["app.acme.test"];

  it("matches the declared host", () => {
    expect(isInScope("https://app.acme.test/path", hosts)).toBe(true);
  });

  it("refuses a different host, even a subdomain or lookalike", () => {
    expect(isInScope("https://evil.test", hosts)).toBe(false);
    expect(isInScope("https://sub.app.acme.test", hosts)).toBe(false);
    expect(isInScope("https://app.acme.test.evil.com", hosts)).toBe(false);
  });

  it("refuses an unparseable URL rather than throwing", () => {
    expect(isInScope("not a url", hosts)).toBe(false);
  });
});

describe("scopedFetch", () => {
  it("calls the base fetch for an in-scope URL", async () => {
    let called: string | null = null;
    const base: typeof fetch = (async (input: RequestInfo | URL) => {
      called = String(input);
      return new Response(null, { status: 204 });
    }) as typeof fetch;

    const response = await scopedFetch(["app.acme.test"], base)("https://app.acme.test/x");
    expect(called).toBe("https://app.acme.test/x");
    expect(response.status).toBe(204);
  });

  it("refuses an out-of-scope URL without ever calling the base fetch", async () => {
    let called = false;
    const base: typeof fetch = (async () => {
      called = true;
      return new Response(null, { status: 200 });
    }) as typeof fetch;

    await expect(scopedFetch(["app.acme.test"], base)("https://evil.test")).rejects.toThrow(
      /outside the declared scope/,
    );
    expect(called).toBe(false);
  });

  it("refuses when the scope is empty, same as any other mismatch", async () => {
    const base: typeof fetch = (async () => new Response(null)) as typeof fetch;
    await expect(scopedFetch([], base)("https://app.acme.test")).rejects.toThrow();
  });
});
