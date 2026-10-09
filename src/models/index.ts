import { ClefClient } from "./clef.js";
import { MatterAIClient } from "./matterai.js";
import type { ModelClient } from "./types.js";

/** What `createModelClient` needs — the AI-facing slice of `Config`. */
export interface ModelConfig {
  readonly aiProvider: "matterai" | "clef";
  readonly aiBaseUrl: string;
  readonly aiApiKey: string;
}

/** Build the client a run's model calls go through. */
export function createModelClient(config: ModelConfig): ModelClient {
  if (config.aiProvider === "clef") {
    return new ClefClient();
  }
  return new MatterAIClient(config.aiBaseUrl, config.aiApiKey);
}

export type { ChatMessage, CompletionOptions, CompletionResult, ModelClient } from "./types.js";
