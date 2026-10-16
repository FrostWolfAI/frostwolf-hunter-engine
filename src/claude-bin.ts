/**
 * Locating the Claude Code CLI (`claude`) portably across Linux and macOS VMs.
 *
 * Resolution order:
 *   1. Explicit `CLAUDE_BIN` environment variable (if readable on disk).
 *   2. Common native install locations (`~/.local/bin/claude`, `/usr/local/bin/claude`,
 *      `/opt/homebrew/bin/claude`, `/usr/bin/claude`).
 *   3. `which claude` on `PATH`.
 *   4. Global npm `@anthropic-ai/claude-code` package (`cli.js`).
 */

import { execFileSync } from "node:child_process";
import { accessSync, constants, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

function isReadable(path: string): boolean {
  try {
    accessSync(path, constants.R_OK);
    return true;
  } catch {
    return false;
  }
}

export function resolveClaudeBin(configured?: string | null): string {
  if (configured !== undefined && configured !== null && configured.trim().length > 0) {
    const raw = configured.trim();
    const absolute = isAbsolute(raw) ? raw : resolve(process.cwd(), raw);
    if (isReadable(absolute)) {
      try {
        return realpathSync(absolute);
      } catch {
        return absolute;
      }
    }
    return "";
  }

  const candidates: string[] = [
    join(homedir(), ".local", "bin", "claude"),
    "/usr/local/bin/claude",
    "/opt/homebrew/bin/claude",
    "/usr/bin/claude",
    "/usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js",
    "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js",
    "/opt/homebrew/lib/node_modules/@anthropic-ai/claude-code/cli.js",
  ];

  try {
    const whichOut = execFileSync("which", ["claude"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
    if (whichOut.length > 0) {
      candidates.unshift(whichOut);
    }
  } catch {
    // `claude` not on PATH
  }

  for (const candidate of candidates) {
    if (candidate.length > 0 && isReadable(candidate)) {
      try {
        return realpathSync(candidate);
      } catch {
        return candidate;
      }
    }
  }

  return "";
}
