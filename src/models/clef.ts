/**
 * Clef, Cloudflare's model — not yet live.
 *
 * Selecting it fails clearly rather than guessing at a contract that does not
 * exist yet. Swap in the real client here once Clef ships; every caller depends
 * only on `ModelClient`, so nothing else needs to change.
 */

import type { CompletionOptions, CompletionResult, ModelClient } from "./types.js";

export class ClefClient implements ModelClient {
  async complete(_options: CompletionOptions): Promise<CompletionResult> {
    throw new Error("Clef is not yet live. Set MODEL_PROVIDER=matterai until it ships.");
  }
}
