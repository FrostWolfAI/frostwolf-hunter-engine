import { mkdtempSync, realpathSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveOrbcodeBin } from "../src/orbcode-bin.js";

describe("resolveOrbcodeBin", () => {
  it("returns an existing configured launcher as an absolute path", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "orb-bin-")));
    const bin = join(dir, "orbcode.js");
    writeFileSync(bin, "// launcher");
    expect(resolveOrbcodeBin(bin)).toBe(bin);
  });

  it("resolves a relative configured path against the process cwd", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "orb-bin-")));
    const bin = join(dir, "orbcode.js");
    writeFileSync(bin, "// launcher");
    expect(resolveOrbcodeBin(relative(process.cwd(), bin))).toBe(bin);
  });

  it("returns \"\" for a configured path that does not exist", () => {
    const dir = realpathSync(mkdtempSync(join(tmpdir(), "orb-bin-")));
    expect(resolveOrbcodeBin(join(dir, "nope", "orbcode.js"))).toBe("");
  });

  it("returns \"\" when nothing is configured and orbcode is not a dependency", () => {
    // The engine does not depend on @matterailab/orbcode, so discovery finds none.
    expect(resolveOrbcodeBin(undefined)).toBe("");
    expect(resolveOrbcodeBin("")).toBe("");
    expect(resolveOrbcodeBin(null)).toBe("");
  });
});
