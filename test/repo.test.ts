import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { isCloneableUrl } from "../src/repo.js";
import { readRepo, readRepoFile } from "../src/repo-read.js";

describe("isCloneableUrl", () => {
  it("accepts a plain public https git URL", () => {
    expect(isCloneableUrl("https://github.com/org/repo")).toBe(true);
    expect(isCloneableUrl("https://gitlab.com/org/repo.git")).toBe(true);
  });

  it("refuses non-https, embedded-credential, and malformed URLs", () => {
    expect(isCloneableUrl("http://github.com/org/repo")).toBe(false);
    expect(isCloneableUrl("ssh://git@github.com/org/repo")).toBe(false);
    expect(isCloneableUrl("git@github.com:org/repo.git")).toBe(false);
    expect(isCloneableUrl("file:///etc")).toBe(false);
    expect(isCloneableUrl("https://user:pass@github.com/org/repo")).toBe(false);
    expect(isCloneableUrl("not a url")).toBe(false);
  });
});

describe("readRepo", () => {
  const dir = mkdtempSync(join(tmpdir(), "hunter-reporead-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  mkdirSync(join(dir, "node_modules", "pkg"), { recursive: true });
  mkdirSync(join(dir, "test"), { recursive: true });
  writeFileSync(join(dir, "src", "auth.js"), "const token = req.headers.authorization;");
  writeFileSync(join(dir, "src", "util.js"), "export const add = (a, b) => a + b;");
  writeFileSync(join(dir, "test", "auth.spec.js"), "it('logs in', () => {});");
  writeFileSync(join(dir, "node_modules", "pkg", "index.js"), "module.exports = {};");
  writeFileSync(join(dir, "README.md"), "# ignored by extension");

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("collects source, ignores node_modules, and ranks security-relevant files first", async () => {
    const digest = await readRepo(dir);
    const paths = digest.files.map((f) => f.path);

    expect(paths).toContain("src/auth.js");
    expect(paths).toContain("src/util.js");
    expect(paths.some((p) => p.startsWith("node_modules/"))).toBe(false);
    expect(paths).not.toContain("README.md"); // not a source extension

    // The auth file outranks a plain util file and a test file.
    expect(paths.indexOf("src/auth.js")).toBeLessThan(paths.indexOf("src/util.js"));
  });

  it("respects the file cap", async () => {
    const digest = await readRepo(dir, { maxFiles: 1, maxFileBytes: 4096, maxTotalBytes: 4096 });
    expect(digest.files).toHaveLength(1);
    expect(digest.files[0]!.path).toBe("src/auth.js"); // highest ranked
  });
});

describe("readRepoFile", () => {
  const dir = mkdtempSync(join(tmpdir(), "hunter-readfile-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(join(dir, "src", "app.js"), "const x = 1;");

  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("reads a file inside the repo", async () => {
    expect(await readRepoFile(dir, "src/app.js")).toBe("const x = 1;");
  });

  it("refuses a path that escapes the repository", async () => {
    expect(await readRepoFile(dir, "../../../etc/passwd")).toBeNull();
    expect(await readRepoFile(dir, "/etc/passwd")).toBeNull();
  });

  it("returns null for a missing file", async () => {
    expect(await readRepoFile(dir, "src/nope.js")).toBeNull();
  });
});
