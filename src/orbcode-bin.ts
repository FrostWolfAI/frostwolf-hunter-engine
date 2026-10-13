/**
 * Locating the orbcode launcher, portably.
 *
 * orbcode is driven as `node <launcher.js>` (see `orbcode.ts`), never through a
 * shell shim, a `.cmd` wrapper, or the executable bit, so one resolution works the
 * same on Linux, macOS and Windows: all we ever need is the path to the launcher's
 * `.js` entry. `node:path` handles each platform's separators, and node's own
 * module resolver finds a bundled install wherever the package manager put it.
 *
 * Resolution order:
 *   1. An explicit `ORBCODE_BIN` — what a deploy image sets. Resolved to an
 *      absolute path (a relative one is taken against the process cwd) and used
 *      only if it exists on disk; a configured-but-missing path resolves to "".
 *   2. orbcode installed as a dependency: its package's `bin`, located through
 *      node's resolver so no `node_modules` layout is assumed.
 *
 * Returns the absolute launcher path, or "" when none is found — the caller then
 * fails the run closed with `orbcode_unavailable` rather than spawning nothing.
 */

import { accessSync, constants } from "node:fs";
import { createRequire } from "node:module";
import { dirname, isAbsolute, resolve } from "node:path";

/** The npm name orbcode publishes under, used for dependency discovery. */
const ORBCODE_PACKAGE = "@matterailab/orbcode";

function isReadable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

/** orbcode bundled as a dependency: read its package `bin`, platform-agnostic. */
function discoverFromDependency(): string {
  try {
    const require = createRequire(import.meta.url);
    const manifestPath = require.resolve(`${ORBCODE_PACKAGE}/package.json`);
    const manifest = require(manifestPath) as { bin?: string | Record<string, string> };
    const relative = typeof manifest.bin === "string" ? manifest.bin : manifest.bin?.orbcode;
    if (relative === undefined || relative.length === 0) {
      return "";
    }
    const absolute = resolve(dirname(manifestPath), relative);
    return isReadable(absolute) ? absolute : "";
  } catch {
    // Not installed as a dependency, or no readable manifest — fall through to "".
    return "";
  }
}

/**
 * Resolve the orbcode launcher path for this host, or "" when none is found.
 *
 * Runs only in the parent process (config load, the local run scripts): it touches
 * the filesystem, which a sandboxed run child cannot. The absolute path it returns
 * is what both the orbcode spawn and the sandbox's read grant are derived from.
 */
export function resolveOrbcodeBin(configured?: string | null): string {
  if (configured !== undefined && configured !== null && configured.length > 0) {
    const absolute = isAbsolute(configured) ? configured : resolve(process.cwd(), configured);
    return isReadable(absolute) ? absolute : "";
  }
  return discoverFromDependency();
}
