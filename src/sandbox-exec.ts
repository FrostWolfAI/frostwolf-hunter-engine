/**
 * `bash` execution — the one tool that runs commands against the target's code.
 *
 * It runs in the parent (the sandboxed child cannot spawn), and it NEVER runs on the
 * host: a command only executes inside a disposable container with gVisor isolation,
 * no network by default, a read-only root, dropped capabilities, a non-root user, and
 * CPU/memory/pid/time caps. Cloned OSS code can run arbitrary install scripts and the
 * agent driving it can be steered by hostile repo content, so host execution is never
 * an option. When no container runtime is configured the runner is **disabled** — every
 * command returns a clear "unavailable" string rather than shelling out locally.
 *
 * The Docker path is written but cannot be exercised in this dev environment; it is
 * gated behind `SANDBOX_RUNTIME=docker` and defaults off. See `HUNTER-STATUS.md`.
 */

import { execFile } from "node:child_process";

export interface ExecResult {
  readonly stdout: string;
  readonly stderr: string;
  readonly code: number | null;
  readonly timedOut: boolean;
}

export interface CommandRunner {
  /** Run one command against the checkout. */
  exec(cmd: string): Promise<ExecResult>;
  /** Tear down the container, if any. */
  dispose(): Promise<void>;
}

/** Bytes of combined output returned to the agent per command. */
const MAX_OUTPUT_BYTES = 16 * 1024;

export interface SandboxConfig {
  readonly runtime: "none" | "docker";
  /** Container image a run executes in. */
  readonly image: string;
  /** Docker `--runtime` (e.g. `runsc` for gVisor), or empty for the default. */
  readonly ociRuntime: string;
  /** Network mode: `none` by default; a scoped network is a later addition. */
  readonly network: string;
  readonly cpus: string;
  readonly memory: string;
  readonly pidsLimit: number;
  /** Per-command wall-clock cap, ms. */
  readonly commandTimeoutMs: number;
}

/** Build the runner a run gets, given the configured runtime and its checkout. */
export function createCommandRunner(config: SandboxConfig, repoDir: string): CommandRunner {
  if (config.runtime === "docker") {
    return new DockerSandbox(config, repoDir);
  }
  return disabledRunner;
}

/** The default: bash is unavailable, and nothing runs on the host. */
export const disabledRunner: CommandRunner = {
  async exec() {
    return {
      stdout: "",
      stderr: "bash is unavailable: no isolated sandbox runtime is configured for this deployment.",
      code: null,
      timedOut: false,
    };
  },
  async dispose() {},
};

/** A command run inside a locked-down, disposable container. */
class DockerSandbox implements CommandRunner {
  private containerId: string | null = null;
  private starting: Promise<string> | null = null;

  constructor(
    private readonly config: SandboxConfig,
    private readonly repoDir: string,
  ) {}

  private async container(): Promise<string> {
    if (this.containerId !== null) {
      return this.containerId;
    }
    this.starting ??= this.start();
    this.containerId = await this.starting;
    return this.containerId;
  }

  private async start(): Promise<string> {
    const args = [
      "run",
      "-d",
      ...(this.config.ociRuntime.length > 0 ? ["--runtime", this.config.ociRuntime] : []),
      "--network",
      this.config.network,
      "--memory",
      this.config.memory,
      "--cpus",
      this.config.cpus,
      "--pids-limit",
      String(this.config.pidsLimit),
      "--cap-drop",
      "ALL",
      "--security-opt",
      "no-new-privileges",
      "--read-only",
      "--tmpfs",
      "/tmp:rw,size=256m",
      // The checkout is the one writable, persistent surface — disposable with the run.
      "-v",
      `${this.repoDir}:/work:rw`,
      "-w",
      "/work",
      "-u",
      "1000:1000",
      this.config.image,
      "sleep",
      String(Math.ceil(this.config.commandTimeoutMs / 1000) * 64),
    ];
    const { stdout } = await this.docker(args, 60_000);
    return stdout.trim();
  }

  async exec(cmd: string): Promise<ExecResult> {
    let id: string;
    try {
      id = await this.container();
    } catch (error) {
      return { stdout: "", stderr: `sandbox did not start: ${msg(error)}`, code: null, timedOut: false };
    }
    try {
      const { stdout, stderr } = await this.docker(
        ["exec", id, "sh", "-lc", cmd],
        this.config.commandTimeoutMs,
      );
      return { stdout: cap(stdout), stderr: cap(stderr), code: 0, timedOut: false };
    } catch (error) {
      const e = error as { stdout?: string; stderr?: string; code?: number; killed?: boolean };
      return {
        stdout: cap(e.stdout ?? ""),
        stderr: cap(e.stderr ?? msg(error)),
        code: typeof e.code === "number" ? e.code : null,
        timedOut: e.killed === true,
      };
    }
  }

  async dispose(): Promise<void> {
    if (this.containerId !== null) {
      await this.docker(["rm", "-f", this.containerId], 30_000).catch(() => undefined);
      this.containerId = null;
    }
  }

  private docker(args: readonly string[], timeoutMs: number): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      execFile("docker", args as string[], { timeout: timeoutMs, maxBuffer: 4 * 1024 * 1024 }, (error, stdout, stderr) => {
        if (error) {
          reject(Object.assign(error, { stdout, stderr }));
        } else {
          resolve({ stdout, stderr });
        }
      });
    });
  }
}

function cap(text: string): string {
  return text.length <= MAX_OUTPUT_BYTES ? text : `${text.slice(0, MAX_OUTPUT_BYTES)}\n…(truncated)`;
}

function msg(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

/** Render an exec result as the single text block the agent sees. */
export function renderExec(result: ExecResult): string {
  const parts: string[] = [];
  if (result.stdout.length > 0) parts.push(result.stdout);
  if (result.stderr.length > 0) parts.push(`[stderr]\n${result.stderr}`);
  if (result.timedOut) parts.push("[command timed out]");
  if (result.code !== null && result.code !== 0) parts.push(`[exit ${result.code}]`);
  return parts.join("\n") || "(no output)";
}
