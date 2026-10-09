/**
 * The judge layer (HUNTER-PLAN.md §3.0, §3.3).
 *
 * A judge is a cheap, low-temperature, structured-output call that gates a
 * stage rather than deciding freely. It is asked for exactly the verdict
 * envelope the plan specifies, grounded only in the evidence it was given. A
 * response that does not parse into that shape is treated as `inconclusive`
 * rather than trusted: an unparseable judge answer is not a judgment, and
 * treating it as one would be the fail-open mistake the independent-judge design
 * exists to prevent. The same applies to a judge call that fails outright.
 *
 * A caller branches only on `verdict.verdict`, and only ever proceeds on
 * `"success"` or `"partial"` — both `"fail"` and the untrusted `"inconclusive"`
 * stop progress. That collapses "the judge said no" and "the judge did not
 * answer" into the same fail-closed outcome, which is the point: neither should
 * let a run proceed.
 */

import { parseLooseJson } from "./json.js";
import type { ModelClient } from "./models/types.js";
import type { JevVerdict } from "./types.js";

const VERDICTS: readonly JevVerdict["verdict"][] = ["success", "partial", "inconclusive", "fail"];
const NEXT: readonly JevVerdict["next"][] = ["verify", "iterate", "falsify", "drop"];

export interface JudgeResult {
  readonly verdict: JevVerdict;
  /** Tokens the judge call spent, or null when the provider did not report it. */
  readonly totalTokens: number | null;
}

function untrusted(gate: string, reason: string): JudgeResult {
  return {
    verdict: {
      gate,
      verdict: "inconclusive",
      confidence: 0,
      evidence_refs: [],
      rationale: `Not judged: ${reason}`,
      next: "drop",
    },
    totalTokens: null,
  };
}

export async function runJudge(
  client: ModelClient,
  model: string,
  gate: string,
  instructions: string,
  evidence: string,
): Promise<JudgeResult> {
  let content: string;
  let totalTokens: number | null;
  try {
    const result = await client.complete({
      model,
      temperature: 0,
      json: true,
      messages: [
        {
          role: "system",
          content:
            `You are the ${gate} for an authorized security assessment of a system whose owner ` +
            "requested this check. Read the instructions and the evidence, then answer with exactly " +
            'one JSON object and nothing else: {"verdict": "success|partial|inconclusive|fail", ' +
            '"confidence": a number from 0 to 1, "evidence_refs": [short strings pointing at the ' +
            'evidence you used], "rationale": a short paragraph, "next": "verify|iterate|falsify|drop"}. ' +
            "Ground the rationale only in the evidence given below. Never invent evidence, and never " +
            "report success without a specific, cited reason.",
        },
        { role: "user", content: `${instructions}\n\nEvidence:\n${evidence}` },
      ],
    });
    content = result.content;
    totalTokens = result.totalTokens;
  } catch (error) {
    return untrusted(gate, error instanceof Error ? error.message : "the judge call failed.");
  }

  const loose = parseLooseJson(content);
  if (loose === null || typeof loose !== "object") {
    return untrusted(gate, "the judge's response was not valid JSON.");
  }
  const parsed = loose as Partial<JevVerdict>;

  if (
    typeof parsed.rationale !== "string" ||
    typeof parsed.confidence !== "number" ||
    !Array.isArray(parsed.evidence_refs) ||
    !VERDICTS.includes(parsed.verdict as JevVerdict["verdict"]) ||
    !NEXT.includes(parsed.next as JevVerdict["next"])
  ) {
    return untrusted(gate, "the judge's response did not match the verdict shape.");
  }

  return {
    verdict: {
      gate,
      verdict: parsed.verdict as JevVerdict["verdict"],
      confidence: Math.min(1, Math.max(0, parsed.confidence)),
      evidence_refs: parsed.evidence_refs.filter((ref): ref is string => typeof ref === "string"),
      rationale: parsed.rationale,
      next: parsed.next as JevVerdict["next"],
    },
    totalTokens,
  };
}

/** A judge backend: given a gate, instructions, and evidence, return a verdict. */
export type Judge = (gate: string, instructions: string, evidence: string) => Promise<JudgeResult>;

/** The LLM judge: the chat model reasons and emits the verdict envelope. */
export function createChatJudge(client: ModelClient, model: string): Judge {
  return (gate, instructions, evidence) => runJudge(client, model, gate, instructions, evidence);
}

/** Map a verdict to the next action a gate takes on it. */
const NEXT_FOR: Record<JevVerdict["verdict"], JevVerdict["next"]> = {
  success: "verify",
  partial: "iterate",
  inconclusive: "drop",
  fail: "falsify",
};

/** What each verdict means, so a criteria-guided decision model can pick one. */
const VERDICT_CRITERIA: Record<JevVerdict["verdict"], string> = {
  success: "the finding is clearly confirmed, or the check clearly passes",
  partial: "the finding is likely but not certain",
  inconclusive: "there is not enough evidence to decide",
  fail: "the finding is not real, or the check fails",
};

/** Cap on the evidence handed to the decision model (its context is small). */
const GLINER_STATE_CHARS = 6000;

/**
 * The GLiNER2.5-Decide judge — a fast, structured JEV decision model (Fastino's
 * `glidecide` / `/v1/systemone`). It returns a `{choice, confidence}` for the
 * verdict rather than reasoning in prose, which is the JEV ideal: a generator
 * proposes, a cheap deterministic judge decides.
 *
 * Caveat, from testing this endpoint: on open-ended *code-exploitability* decisions
 * it does not currently discriminate well (it inverted real vs. benign snippets), so
 * it is not a safe default for the success/verification truth-gates — keep those on
 * the LLM. It is well-suited to structured classification gates (severity, novelty)
 * where the decision maps to clear textual signals. This backend is therefore
 * selectable per deployment, not the default. Any failure is fail-closed.
 */
export function createGlinerJudge(baseUrl: string, fetchFn: typeof fetch = fetch): Judge {
  const url = `${baseUrl.replace(/\/$/, "")}/v1/systemone`;
  return async (gate, instructions, evidence) => {
    let body: unknown;
    try {
      const response = await fetchFn(url, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          state: `${instructions}\n\n${evidence}`.slice(0, GLINER_STATE_CHARS),
          questions: {
            verdict: {
              type: "choice",
              instructions: `You are the ${gate}. Decide the verdict for this security assessment step.`,
              criteria: VERDICT_CRITERIA,
            },
          },
        }),
      });
      if (!response.ok) {
        return untrusted(gate, `glidecide returned ${response.status}`);
      }
      body = await response.json();
    } catch (error) {
      return untrusted(gate, error instanceof Error ? error.message : "glidecide call failed.");
    }

    const answer = (body as { answers?: { verdict?: { choice?: unknown; confidence?: unknown } } })
      ?.answers?.verdict;
    const choice = answer?.choice;
    if (typeof choice !== "string" || !VERDICTS.includes(choice as JevVerdict["verdict"])) {
      return untrusted(gate, "glidecide returned no usable verdict.");
    }
    const verdict = choice as JevVerdict["verdict"];
    const confidence = typeof answer?.confidence === "number" ? Math.min(1, Math.max(0, answer.confidence)) : 0;
    return {
      verdict: {
        gate,
        verdict,
        confidence,
        evidence_refs: [],
        rationale: `GLiNER2.5-Decide: ${verdict} (${confidence.toFixed(2)})`,
        next: NEXT_FOR[verdict],
      },
      totalTokens: null,
    };
  };
}
