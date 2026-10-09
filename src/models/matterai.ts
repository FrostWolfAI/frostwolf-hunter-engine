/**
 * Client for matterai.so's inference API.
 *
 * matterai.so is an inference gateway in front of several model families,
 * including GLM 5.3. This client speaks the OpenAI chat-completions shape, which
 * is the de facto standard most inference gateways of this kind expose — it has
 * not been verified against matterai.so's own reference docs. Confirm the path
 * and the response shape once you have them; everything else in the engine
 * depends only on `ModelClient`, so a mismatch here is a one-file fix, and the
 * base URL is already configuration (`MATTERAI_BASE_URL`) rather than hardcoded.
 */

import type { ChatMessage, CompletionOptions, CompletionResult, ModelClient } from "./types.js";

const DEFAULT_TEMPERATURE = 0.7;

export class MatterAIClient implements ModelClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
  ) {}

  async complete(options: CompletionOptions): Promise<CompletionResult> {
    const response = await fetch(`${this.baseUrl.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: {
        authorization: `Bearer ${this.apiKey}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({
        model: options.model,
        messages: options.messages satisfies readonly ChatMessage[],
        temperature: options.temperature ?? DEFAULT_TEMPERATURE,
        ...(options.json === true ? { response_format: { type: "json_object" } } : {}),
      }),
    });

    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new Error(`matterai.so returned ${response.status}: ${body.slice(0, 500)}`);
    }

    const body = (await response.json()) as {
      choices?: Array<{ message?: { content?: string } }>;
      usage?: { total_tokens?: number };
    };
    const content = body.choices?.[0]?.message?.content;
    if (typeof content !== "string") {
      throw new Error("matterai.so response carried no message content.");
    }

    return { content, totalTokens: body.usage?.total_tokens ?? null };
  }
}
