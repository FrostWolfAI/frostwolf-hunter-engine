/**
 * Enforcing the declared scope on outbound requests.
 *
 * "sandbox egress allowlist == declared scope" (HUNTER-PLAN.md §9.4) is enforced
 * here, at the application level: every call a stage makes at a target goes
 * through `scopedFetch`, which refuses anything whose host is not in the hunt's
 * declared `scope.hosts`.
 *
 * This is NOT yet an OS-level network boundary. Node's permission model
 * (`src/sandbox.ts`) restricts the filesystem and child-process spawning, but as
 * of this Node version it has no network-permission flag, so a compromised stage
 * could still open a raw socket outside this wrapper. The ceiling on what may run
 * inside the sandbox today is therefore "code this service shipped," not
 * "arbitrary code" — every stage is code we wrote, and this wrapper is the
 * control for that code. An OS-level egress boundary (a network namespace or an
 * enforcing proxy) is required before the sandbox runs anything less trusted —
 * repo-derived code, or a fully autonomous request-crafting loop — and is not
 * built yet.
 */

import type { RunJob } from "./types.js";

/** The declared scope's target hosts, or an empty list. */
export function scopeHosts(job: RunJob): string[] {
  const hosts = job.scope.hosts;
  return Array.isArray(hosts) ? hosts.filter((h): h is string => typeof h === "string") : [];
}

/** The declared repository URL, or null. The subject of white-box analysis. */
export function scopeRepo(job: RunJob): string | null {
  const repo = job.scope.repo;
  return typeof repo === "string" && repo.length > 0 ? repo : null;
}

/** Whether a URL's host is in the allowlist. An unparseable URL is never in scope. */
export function isInScope(url: string, hosts: readonly string[]): boolean {
  try {
    return hosts.includes(new URL(url).host);
  } catch {
    return false;
  }
}

/**
 * A `fetch` that refuses any request outside the declared scope.
 *
 * `base` defaults to the real `fetch` and is overridable only for tests, so
 * nothing outside a test can quietly swap out the function doing the enforcing.
 */
export function scopedFetch(hosts: readonly string[], base: typeof fetch = fetch): typeof fetch {
  return (async (input, init) => {
    const url =
      typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (!isInScope(url, hosts)) {
      throw new Error(
        `refused: ${url} is outside the declared scope (${hosts.join(", ") || "none"}).`,
      );
    }
    return base(input, init);
  }) as typeof fetch;
}
