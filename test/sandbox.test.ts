import { mkdirSync, mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { fork } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { sandboxOptions } from "../src/sandbox.js";

/** What a hostile run could try, reported back over IPC. */
const PROBE = `
const fs = require("node:fs");
const cp = require("node:child_process");
const attempt = (fn) => { try { fn(); return "allowed"; } catch { return "denied"; } };
process.send({
  secret: process.env.HUNTER_SECRET ?? null,
  redis: process.env.REDIS_URL ?? null,
  readOutside: attempt(() => fs.readFileSync("/etc/hosts")),
  writeFile: attempt(() => fs.writeFileSync(require("node:path").join(require("node:os").tmpdir(), "fw-escape"), "x")),
  spawn: attempt(() => cp.execSync("echo hi")),
}, () => process.exit(0));
`;

describe("sandbox", () => {
  it("gives a run no secrets, no outside files, and no processes", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "fw-sandbox-")));
    writeFileSync(join(dir, "probe.cjs"), PROBE);

    // The parent holds the secrets, as the real service does.
    process.env.HUNTER_SECRET = "must-not-leak";
    process.env.REDIS_URL = "redis://must-not-leak";

    const report = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const child = fork(join(dir, "probe.cjs"), [], {
        ...sandboxOptions(dir),
        stdio: ["ignore", "inherit", "inherit", "ipc"],
      });
      child.once("message", (message) => resolve(message as Record<string, unknown>));
      child.once("error", reject);
      child.once("exit", (code) => code !== 0 && reject(new Error(`exited ${code}`)));
    });

    expect(report).toEqual({
      secret: null,
      redis: null,
      readOutside: "denied",
      writeFile: "denied",
      spawn: "denied",
    });
  });

  it("can read a granted repo directory but still not write it or escape it", async () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "fw-sandbox-")));
    const repo = realpathSync(mkdtempSync(join(tmpdir(), "fw-repo-")));
    mkdirSync(join(repo, "src"), { recursive: true });
    writeFileSync(join(repo, "src", "app.js"), "const x = 1;");

    const probe = `
const fs = require("node:fs");
const attempt = (fn) => { try { return fn(); } catch { return "denied"; } };
process.send({
  readRepo: attempt(() => fs.readFileSync(${JSON.stringify(join(repo, "src", "app.js"))}, "utf8")),
  writeRepo: attempt(() => { fs.writeFileSync(${JSON.stringify(join(repo, "evil.js"))}, "x"); return "allowed"; }),
  readOutside: attempt(() => { fs.readFileSync("/etc/hosts"); return "allowed"; }),
}, () => process.exit(0));
`;
    writeFileSync(join(dir, "probe.cjs"), probe);

    const report = await new Promise<Record<string, unknown>>((resolve, reject) => {
      const child = fork(join(dir, "probe.cjs"), [], {
        // The repo is granted read, exactly as the runner grants the clone.
        ...sandboxOptions(dir, repo),
        stdio: ["ignore", "inherit", "inherit", "ipc"],
      });
      child.once("message", (message) => resolve(message as Record<string, unknown>));
      child.once("error", reject);
      child.once("exit", (code) => code !== 0 && reject(new Error(`exited ${code}`)));
    });

    expect(report).toEqual({
      readRepo: "const x = 1;",
      writeRepo: "denied",
      readOutside: "denied",
    });
  });
});
