/**
 * Reading a cloned repository into a bounded digest — child side.
 *
 * This runs inside the run's child process, which has read-only access to the
 * checkout and nothing else. It never executes repository code: it walks the tree,
 * selects the files most likely to carry logic worth red-teaming, and returns them
 * as text, under hard caps so one enormous repo cannot blow the token budget or the
 * heap. Everything downstream (recon, synthesis, validation) reasons over this
 * digest, never over the live filesystem.
 */

import type { Dirent } from "node:fs";
import { readFile, readdir, stat } from "node:fs/promises";
import { join, relative, resolve, sep } from "node:path";

/** Hard caps so a run stays bounded regardless of repository size. */
export interface ReadLimits {
  readonly maxFiles: number;
  readonly maxFileBytes: number;
  readonly maxTotalBytes: number;
}

export const DEFAULT_LIMITS: ReadLimits = {
  maxFiles: 60,
  maxFileBytes: 48 * 1024,
  maxTotalBytes: 450 * 1024,
};

/** One selected source file. */
export interface SourceFile {
  readonly path: string;
  readonly content: string;
  readonly truncated: boolean;
}

/** The digest handed to the models. */
export interface RepoDigest {
  /** Every file path in the tree (after the ignore filter), for the model's map. */
  readonly tree: readonly string[];
  /** The highest-ranked files, with contents, under the caps. */
  readonly files: readonly SourceFile[];
  readonly totalFilesSeen: number;
}

/** Directories never worth reading. */
const IGNORE_DIRS = new Set([
  ".git",
  "node_modules",
  "vendor",
  "dist",
  "build",
  "out",
  ".next",
  "target",
  "__pycache__",
  ".venv",
  "venv",
  ".cache",
  "coverage",
  "testdata",
  "fixtures",
]);

/** Extensions worth reading as source. */
const SOURCE_EXT = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rb", ".php", ".java", ".kt", ".cs", ".rs",
  ".sql", ".graphql", ".proto",
  ".yaml", ".yml", ".toml", ".json", ".env",
  ".tf", ".hcl", ".dockerfile",
]);

/** Files whose name alone marks them as high value. */
const HIGH_VALUE_NAMES = new Set([
  "dockerfile", "docker-compose.yml", "docker-compose.yaml",
  "package.json", "requirements.txt", "go.mod", "pom.xml",
  "schema.sql", "schema.prisma",
]);

/**
 * Score a path by how likely it is to hold a production-relevant flaw.
 *
 * Auth, routing, request handling, access control, tool/agent definitions, and
 * data access rank highest — these are where logic and architecture flaws live,
 * the ones that carry no CVE. Tests and generated code rank lowest.
 */
function score(path: string): number {
  const p = path.toLowerCase();
  let s = 0;
  for (const [needle, weight] of [
    ["auth", 6], ["session", 5], ["login", 5], ["password", 4], ["token", 4],
    ["permission", 6], ["access", 4], ["role", 4], ["tenant", 6], ["admin", 4],
    ["route", 5], ["handler", 5], ["controller", 5], ["api", 4], ["endpoint", 5],
    ["middleware", 5], ["guard", 5], ["validate", 3], ["sanitiz", 3],
    ["query", 4], ["db", 3], ["sql", 4], ["model", 2], ["repository", 3],
    ["tool", 4], ["agent", 4], ["prompt", 4], ["exec", 4], ["eval", 4],
    ["upload", 4], ["file", 2], ["webhook", 4], ["payment", 5], ["billing", 4],
    ["config", 2], ["secret", 4], ["crypto", 3],
  ] as const) {
    if (p.includes(needle)) {
      s += weight;
    }
  }
  if (p.includes("test") || p.includes("spec") || p.includes(".min.")) {
    s -= 8;
  }
  const base = p.split("/").pop() ?? "";
  if (HIGH_VALUE_NAMES.has(base)) {
    s += 5;
  }
  // Shallow files (closer to the root) tend to be more structural.
  s -= (p.split("/").length - 1) * 0.3;
  return s;
}

/** Whether a file is worth reading at all. */
function isSource(path: string): boolean {
  const base = (path.split("/").pop() ?? "").toLowerCase();
  if (HIGH_VALUE_NAMES.has(base) || base === "dockerfile") {
    return true;
  }
  const dot = base.lastIndexOf(".");
  const ext = dot === -1 ? "" : base.slice(dot);
  return SOURCE_EXT.has(ext);
}

/**
 * Every source file in the repository, repo-relative, ignore-filtered.
 *
 * Shared by `readRepo` and by the agent's `search` tool, so both see the same
 * universe of files (and neither ever walks into `node_modules`, `.git`, etc.).
 */
export async function listSourceFiles(repoDir: string): Promise<string[]> {
  const candidates: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    let entries: Dirent[];
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name.startsWith(".") && entry.name !== ".env" && entry.isDirectory()) {
        continue;
      }
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!IGNORE_DIRS.has(entry.name)) {
          await walk(full);
        }
      } else if (entry.isFile()) {
        const rel = relative(repoDir, full).split(sep).join("/");
        if (isSource(rel)) {
          candidates.push(rel);
        }
      }
    }
  };
  await walk(repoDir);
  return candidates;
}

/** Rank a list of paths by how likely they are to hold a production-relevant flaw. */
export function rankPaths(paths: readonly string[]): string[] {
  return [...paths].sort((a, b) => score(b) - score(a));
}

/** Collect a bounded, ranked digest of a repository. */
export async function readRepo(
  repoDir: string,
  limits: ReadLimits = DEFAULT_LIMITS,
): Promise<RepoDigest> {
  const candidates = await listSourceFiles(repoDir);
  const ranked = rankPaths(candidates);

  const files: SourceFile[] = [];
  let totalBytes = 0;
  for (const rel of ranked) {
    if (files.length >= limits.maxFiles || totalBytes >= limits.maxTotalBytes) {
      break;
    }
    let raw: string;
    try {
      raw = await readText(join(repoDir, rel), limits.maxFileBytes);
    } catch {
      continue;
    }
    const truncated = raw.length >= limits.maxFileBytes;
    files.push({ path: rel, content: raw, truncated });
    totalBytes += raw.length;
  }

  return { tree: candidates.sort(), files, totalFilesSeen: candidates.length };
}

/** Read up to `maxBytes` of a file as UTF-8 text. */
async function readText(path: string, maxBytes: number): Promise<string> {
  const size = (await stat(path)).size;
  const buffer = await readFile(path);
  return buffer.subarray(0, Math.min(size, maxBytes)).toString("utf8");
}

/**
 * Read one repository-relative file, refusing any path that escapes the checkout.
 *
 * A model-proposed path like `../../etc/passwd` resolves outside `repoDir` and is
 * refused — the one place a model's output names a filesystem path, so the one
 * place path traversal has to be checked. Returns null when the file is missing,
 * outside the repo, or unreadable.
 */
export async function readRepoFile(
  repoDir: string,
  relPath: string,
  maxFileBytes: number = DEFAULT_LIMITS.maxFileBytes,
): Promise<string | null> {
  const root = resolve(repoDir);
  const full = resolve(root, relPath);
  if (full !== root && !full.startsWith(root + sep)) {
    return null;
  }
  try {
    return await readText(full, maxFileBytes);
  } catch {
    return null;
  }
}
