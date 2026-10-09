/**
 * The interface every model call goes through.
 *
 * The attacker brain, the verifier brain, and every judge all speak this one
 * shape. Nothing downstream of `ModelClient` knows or cares which provider is
 * behind it — that is the model-agnostic requirement in HUNTER-PLAN.md §4b: the
 * model id is configuration, never hardcoded, so a customer or a hunt can swap
 * providers without a code change.
 */

export interface ChatMessage {
  readonly role: "system" | "user" | "assistant";
  readonly content: string;
}

export interface CompletionOptions {
  readonly model: string;
  readonly messages: readonly ChatMessage[];
  /** Defaults to a conversational temperature; judges pass 0. */
  readonly temperature?: number;
  /** Ask the provider to constrain output to a single JSON object. */
  readonly json?: boolean;
}

export interface CompletionResult {
  readonly content: string;
  /** Null when the provider did not report usage. */
  readonly totalTokens: number | null;
}

export interface ModelClient {
  complete(options: CompletionOptions): Promise<CompletionResult>;
}
