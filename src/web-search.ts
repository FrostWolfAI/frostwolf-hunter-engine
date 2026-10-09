/**
 * `web_search` — background lookups for the agent, via Fireworks.
 *
 * It runs in the parent (the sandboxed child holds no key and makes no such call)
 * and returns a compact text list of results the agent can read. It is a background
 * aid — framework docs, a technique, a config default — not a channel to the target.
 *
 * Disabled until `FIREWORKS_API_KEY` is set. The request/response shape below is the
 * common one and has NOT been verified against Fireworks' actual web-search API;
 * confirm the endpoint and fields once the key and docs are in hand, and adjust this
 * one file — every caller depends only on `WebSearch`. See `HUNTER-STATUS.md`.
 */

export interface WebSearch {
  search(query: string): Promise<string>;
}

/** The default: web search is unavailable. */
export const disabledWebSearch: WebSearch = {
  async search() {
    return "web_search is unavailable: no search key is configured for this deployment.";
  },
};

export interface WebSearchConfig {
  readonly apiKey: string;
  readonly baseUrl: string;
  readonly maxResults: number;
}

export function createWebSearch(config: WebSearchConfig): WebSearch {
  if (config.apiKey.trim().length === 0) {
    return disabledWebSearch;
  }
  return new FireworksWebSearch(config);
}

class FireworksWebSearch implements WebSearch {
  constructor(private readonly config: WebSearchConfig) {}

  async search(query: string): Promise<string> {
    if (query.trim().length === 0) {
      return "error: empty query";
    }
    let response: Response;
    try {
      response = await fetch(`${this.config.baseUrl.replace(/\/$/, "")}/search`, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.config.apiKey}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({ query, max_results: this.config.maxResults }),
      });
    } catch (error) {
      return `web_search failed: ${error instanceof Error ? error.message : "unreachable"}`;
    }
    if (!response.ok) {
      return `web_search failed: provider returned ${response.status}`;
    }

    // Tolerant of a few likely shapes until the real one is confirmed.
    const body = (await response.json().catch(() => null)) as
      | { results?: Array<{ title?: string; url?: string; snippet?: string; content?: string }> }
      | null;
    const results = body?.results ?? [];
    if (results.length === 0) {
      return `no results for "${query}"`;
    }
    return results
      .slice(0, this.config.maxResults)
      .map((r) => `- ${r.title ?? r.url ?? "result"}\n  ${r.url ?? ""}\n  ${(r.snippet ?? r.content ?? "").slice(0, 300)}`)
      .join("\n");
  }
}
