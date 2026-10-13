import { describe, expect, it } from "vitest";
import { createCommandRunner, type SandboxConfig } from "../src/sandbox-exec.js";

const CONFIG: SandboxConfig = {
  image: "node:22-slim",
  ociRuntime: "",
  network: "none",
  cpus: "1",
  memory: "512m",
  pidsLimit: 128,
  commandTimeoutMs: 1_000,
};

describe("sandbox-exec", () => {
  it("always returns a container-backed runner — the sandbox is never disabled", async () => {
    const runner = createCommandRunner(CONFIG, "/tmp/frostwolf-sandbox-test");
    const result = await runner.exec("echo hi");
    // There is no disabled no-op path any more. Without a container runtime on the
    // host a command fails trying to start the sandbox; it never silently reports
    // "unavailable" without attempting it, and it never shells out on the host.
    expect(result.stderr).not.toMatch(/no isolated sandbox runtime/i);
    expect(result.stderr).toMatch(/sandbox did not start/i);
    await runner.dispose();
  });
});
