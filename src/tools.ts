/**
 * The tools the agent drives — Hunter's equivalent of a coding agent's tool belt.
 *
 * Two kinds, split by where they run and what they can touch:
 *
 *  - **Local, read-only tools** run inside the sandboxed child against the cloned
 *    checkout: `read_file`, `list_dir`, `search`. They cannot write, spawn, or reach
 *    the network, and every path is traversal-guarded and every result capped.
 *  - **Brokered tools** are the privileged ones — `bash` (run a command against the
 *    code) and `web_search` (look something up). The child cannot do these itself: it
 *    asks the parent over IPC, the parent runs them in the run's container / with the
 *    search key, and hands back the text. So the child never holds a key, never
 *    spawns, and `bash` only ever runs inside a real isolation boundary.
 *
 * A toolset is just a name→runner map plus the docs the model is shown, so a run
 * gets exactly the tools that are actually available to it (bash only when a
 * container runtime is configured, web_search only when a search key is set).
 */

import { readdir } from "node:fs/promises";
import { resolve, sep } from "node:path";
import { listSourceFiles, readRepoFile } from "./repo-read.js";

/** One tool invocation, as the model names it. */
export interface ToolCall {
  readonly tool: string;
  readonly args: Record<string, unknown>;
}

/** A runnable tool: the one-line doc the model sees, and the implementation. */
export interface Tool {
  readonly describe: string;
  run(args: Record<string, unknown>): Promise<string>;
}

/** A ready-to-drive toolset: the docs block and a dispatcher. */
export interface Toolset {
  readonly docs: string;
  run(call: ToolCall): Promise<string>;
}

// --- caps so no single tool call can blow the budget -----------------------
const MAX_LIST_ENTRIES = 200;
const MAX_FILE_BYTES = 48 * 1024;
const MAX_SEARCH_HITS = 40;
const MAX_SEARCH_FILES = 1500;
const SNIPPET_CHARS = 200;
const MAX_RESULT_CHARS = 6000;

const IGNORE_DIRS = new Set([
  ".git", "node_modules", "vendor", "dist", "build", "out", ".next", "target",
  "__pycache__", ".venv", "venv", ".cache", "coverage",
]);

/** The local, read-only tools, bound to one checkout. */
export class RepoTools {
  private readonly root: string;
  private sourceList: string[] | null = null;

  constructor(repoDir: string) {
    this.root = resolve(repoDir);
  }

  private safe(rel: string): string | null {
    const full = resolve(this.root, rel);
    return full === this.root || full.startsWith(this.root + sep) ? full : null;
  }

  async listDir(rel: string): Promise<string> {
    const full = this.safe(rel);
    if (full === null) {
      return "error: path escapes the repository";
    }
    try {
      const entries = await readdir(full, { withFileTypes: true });
      const lines = entries
        .filter((e) => !(e.isDirectory() && IGNORE_DIRS.has(e.name)))
        .slice(0, MAX_LIST_ENTRIES)
        .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
        .sort();
      return lines.length === 0 ? "(empty)" : lines.join("\n");
    } catch {
      return `error: cannot list "${rel || "."}"`;
    }
  }

  async readFile(rel: string): Promise<string> {
    const content = await readRepoFile(this.root, rel, MAX_FILE_BYTES);
    return content === null ? `error: cannot read "${rel}"` : content;
  }

  async search(query: string): Promise<string> {
    if (query.length === 0) {
      return "error: empty query";
    }
    this.sourceList ??= await listSourceFiles(this.root);
    const needle = query.toLowerCase();
    const hits: string[] = [];
    let scanned = 0;
    for (const rel of this.sourceList) {
      if (hits.length >= MAX_SEARCH_HITS || scanned >= MAX_SEARCH_FILES) {
        break;
      }
      scanned += 1;
      const content = await readRepoFile(this.root, rel, MAX_FILE_BYTES);
      if (content === null || !content.toLowerCase().includes(needle)) {
        continue;
      }
      const lines = content.split("\n");
      for (let i = 0; i < lines.length && hits.length < MAX_SEARCH_HITS; i++) {
        if (lines[i]!.toLowerCase().includes(needle)) {
          hits.push(`${rel}:${i + 1}: ${lines[i]!.trim().slice(0, SNIPPET_CHARS)}`);
        }
      }
    }
    return hits.length === 0 ? `no matches for "${query}"` : hits.join("\n");
  }
}

/** A privileged tool brokered to the parent, or null when it is not available. */
export type BrokeredTool = ((args: Record<string, unknown>) => Promise<string>) | null;

/** Assemble the toolset a run actually gets, given what is available. */
export function buildToolset(
  repo: RepoTools,
  brokered: { readonly bash?: BrokeredTool; readonly webSearch?: BrokeredTool } = {},
): Toolset {
  const str = (args: Record<string, unknown>, key: string): string =>
    typeof args[key] === "string" ? (args[key] as string) : "";

  const tools: Record<string, Tool> = {
    list_dir: {
      describe: 'list_dir(path): list a directory ("" = repo root).',
      run: (a) => repo.listDir(str(a, "path")),
    },
    read_file: {
      describe: "read_file(path): return a file's contents.",
      run: (a) => repo.readFile(str(a, "path")),
    },
    search: {
      describe:
        "search(query): find a substring across all source files; returns path:line " +
        "matches. Use it to follow a symbol, route, or sink across files.",
      run: (a) => repo.search(str(a, "query")),
    },
  };

  if (brokered.bash) {
    const bash = brokered.bash;
    tools.bash = {
      describe:
        "bash(cmd): run a shell command against the checked-out code in the isolated " +
        "sandbox (e.g. build it, run a script, inspect output). Read-mostly; the " +
        "sandbox is disposable and has no access to anything outside the run.",
      run: (a) => bash({ cmd: str(a, "cmd") }),
    };
  }
  if (brokered.webSearch) {
    const webSearch = brokered.webSearch;
    tools.web_search = {
      describe: "web_search(query): search the web for background (framework docs, a technique).",
      run: (a) => webSearch({ query: str(a, "query") }),
    };
  }

  const docs =
    "You can call these tools to explore before you answer:\n" +
    Object.values(tools)
      .map((t) => `- ${t.describe}`)
      .join("\n");

  return {
    docs,
    async run(call) {
      const tool = tools[call.tool];
      if (tool === undefined) {
        return `error: unknown or unavailable tool "${call.tool}"`;
      }
      try {
        return truncate(await tool.run(call.args));
      } catch (error) {
        return `error: ${error instanceof Error ? error.message : "tool failed"}`;
      }
    },
  };
}

/** Keep a tool result from overrunning the context. */
export function truncate(text: string, max = MAX_RESULT_CHARS): string {
  return text.length <= max ? text : `${text.slice(0, max)}\n…(truncated)`;
}

/** Normalise whatever the model returned into a list of tool calls. */
export function parseToolCalls(value: unknown): ToolCall[] {
  const raw = Array.isArray(value) ? value : [];
  const calls: ToolCall[] = [];
  for (const item of raw) {
    if (item !== null && typeof item === "object") {
      const tool = (item as Record<string, unknown>).tool;
      const args = (item as Record<string, unknown>).args;
      if (typeof tool === "string") {
        calls.push({
          tool,
          args: args !== null && typeof args === "object" ? (args as Record<string, unknown>) : {},
        });
      }
    }
  }
  return calls;
}
