/**
 * Cloning a target repository — parent side only.
 *
 * This runs in the parent service, never in a run's child: the child has no spawn
 * permission and an empty environment, so it cannot and must not clone. The parent
 * does a shallow, single-branch, no-credential clone of a **public** Git URL into a
 * throwaway directory, hands the path to the child read-only, and deletes it when
 * the run ends.
 *
 * Only `https://` Git URLs are accepted. An `ssh://` or `file://` URL, or anything
 * that would let the clone read the host's own filesystem or reach a private host
 * by SSH key, is refused — for now Hunter targets open-source repositories and
 * carries no customer Git credential, so a non-public URL is always a mistake or
 * worse.
 */

import { execFile } from "node:child_process";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/** How long a clone may take before it is abandoned. */
const CLONE_TIMEOUT_MS = 120_000;
/** Cap the checkout so a huge repo cannot fill the disk. */
const MAX_CHECKOUT_BYTES = 500 * 1024 * 1024;

/** A cloned repository and the means to delete it. */
export interface PreparedRepo {
  readonly dir: string;
  cleanup(): Promise<void>;
}

/** Whether a URL is a public `https://` Git URL we will clone. */
export function isCloneableUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") {
    return false;
  }
  // No embedded credentials, and a real host.
  return parsed.username === "" && parsed.password === "" && parsed.hostname.length > 0;
}

/**
 * Shallow-clone a public repository into a throwaway directory.
 *
 * Throws on a refused URL or a failed clone; the caller fails the run closed.
 */
export async function cloneRepo(url: string): Promise<PreparedRepo> {
  if (!isCloneableUrl(url)) {
    throw new Error(`refusing to clone a non-public or malformed URL: ${url}`);
  }

  const dir = await mkdtemp(join(tmpdir(), "hunter-repo-"));
  const cleanup = async (): Promise<void> => {
    await rm(dir, { recursive: true, force: true }).catch(() => undefined);
  };

  try {
    await new Promise<void>((resolve, reject) => {
      const child = execFile(
        "git",
        [
          "-c",
          "credential.helper=",
          "-c",
          "core.askpass=true",
          "clone",
          "--depth",
          "1",
          "--single-branch",
          "--no-tags",
          url,
          dir,
        ],
        {
          timeout: CLONE_TIMEOUT_MS,
          maxBuffer: 8 * 1024 * 1024,
          // An empty askpass + disabled credential helper means a private repo
          // cannot silently prompt or pull an ambient credential: it just fails.
          env: {
            PATH: process.env.PATH ?? "",
            GIT_TERMINAL_PROMPT: "0",
            GIT_ASKPASS: "true",
          },
        },
        (error) => (error ? reject(error) : resolve()),
      );
      child.on("error", reject);
    });

    await enforceSizeCap(dir);
    return { dir, cleanup };
  } catch (error) {
    await cleanup();
    throw error instanceof Error ? error : new Error("clone failed");
  }
}

/** Delete the checkout if it blew past the size cap. */
async function enforceSizeCap(dir: string): Promise<void> {
  const { stat, readdir } = await import("node:fs/promises");
  let total = 0;
  const walk = async (path: string): Promise<void> => {
    const entries = await readdir(path, { withFileTypes: true });
    for (const entry of entries) {
      const full = join(path, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.isFile()) {
        total += (await stat(full)).size;
        if (total > MAX_CHECKOUT_BYTES) {
          throw new Error("repository exceeds the checkout size cap");
        }
      }
    }
  };
  await walk(dir);
}
