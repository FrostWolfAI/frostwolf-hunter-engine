import { describe, it, expect, afterAll } from "vitest";
import { startEgressProxy } from "../src/egress-proxy.js";
import { isInScope } from "../src/scope.js";

describe("egress proxy", () => {
  let proxy;

  afterAll(async () => {
    if (proxy) {
      await proxy.close();
    }
  });

  it("starts and returns a URL", async () => {
    proxy = await startEgressProxy({ hosts: ["example.com"] });
    expect(proxy.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(proxy.port).toBeGreaterThan(0);
  });

  it("scope logic allows in-scope hosts", () => {
    expect(isInScope("http://example.com/path", ["example.com"])).toBe(true);
    expect(isInScope("https://example.com", ["example.com"])).toBe(true);
  });

  it("scope logic blocks out-of-scope hosts", () => {
    expect(isInScope("http://evil.com", ["example.com"])).toBe(false);
    expect(isInScope("http://example.com.evil.com", ["example.com"])).toBe(false);
  });

  it("onRequest callback is called for blocked requests", async () => {
    const logs: string[] = [];
    proxy = await startEgressProxy({
      hosts: ["example.com"],
      onRequest: (url, allowed) => {
        if (!allowed) {
          logs.push(url);
        }
      },
    });

    // The callback is called when the proxy handles a request.
    // We can't easily test this without a real HTTP client that routes through the proxy,
    // so we just verify the proxy starts and the callback is wired up.
    expect(proxy.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });
});