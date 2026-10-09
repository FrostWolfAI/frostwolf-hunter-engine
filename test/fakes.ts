import type { ModelClient } from "../src/models/types.js";
import type { PreparedRepo } from "../src/repo.js";
import { disabledRunner } from "../src/sandbox-exec.js";
import { disabledWebSearch } from "../src/web-search.js";
import type { RunCredentials } from "../src/types.js";

/** Dummy but non-empty credentials, so the pipeline's AI-config check passes. */
export const FAKE_CREDENTIALS: RunCredentials = {
  aiProvider: "matterai",
  aiBaseUrl: "https://matterai.test",
  aiApiKey: "test-key",
  attackerModel: "test-attacker",
  verifierModel: "test-verifier",
  judgeModel: "test-judge",
  verifyN: 2,
  costPer1kTokensUsd: 0.001,
  maxRunTokens: 1_000_000,
  agentRuntime: "internal",
  orbcodeBin: "",
  judgeProvider: "chat",
  judgeBaseUrl: "",
};

/** The tool-related `processRun` deps for a test, with bash + web search off. */
export const baseToolDeps = {
  capabilities: { bash: false, webSearch: false },
  makeCommandRunner: () => disabledRunner,
  webSearch: disabledWebSearch,
};

type Verdict = "success" | "partial" | "inconclusive" | "fail";

/** A judge reply in the exact envelope `runJudge` expects. */
function judgeReply(verdict: Verdict) {
  return {
    content: JSON.stringify({
      verdict,
      confidence: 0.9,
      evidence_refs: ["src/auth.js:10"],
      rationale: "scripted for a test",
      next: verdict === "fail" ? "falsify" : "verify",
    }),
    totalTokens: 8,
  };
}

/** What a test can force at each gate / step. */
export interface ScriptOutcomes {
  readonly plausibility?: Verdict;
  readonly adjudicator?: Verdict;
  readonly verification?: Verdict;
  /** Whether the attacker brain constructs a usable proof in the exploit stage. */
  readonly provable?: boolean;
  /** The exploit stage's judge: does the construction hold up. */
  readonly exploitAdjudicator?: Verdict;
  /** Whether the independent verifier model says the flaw exists. */
  readonly verifierExists?: boolean;
  /** How many hypotheses synthesis proposes. Default 1. */
  readonly hypotheses?: number;
}

/**
 * A `ModelClient` that drives the real white-box pipeline deterministically.
 *
 * It answers each step by the model it is called on (matching `FAKE_CREDENTIALS`)
 * and the gate/step named in the prompt, so a test exercises the genuine stage
 * logic — recon, synthesis, the judges, independent verification — without a live
 * matterai.so account. Hypotheses reference `src/auth.js`, which the fixture repo
 * (`createFixtureRepo`) actually contains, so validation finds real code to read.
 */
export function scriptedModel(outcomes: ScriptOutcomes = {}): ModelClient {
  const plausibility = outcomes.plausibility ?? "success";
  const adjudicator = outcomes.adjudicator ?? "success";
  const verification = outcomes.verification ?? "success";
  const provable = outcomes.provable ?? true;
  const exploitAdjudicator = outcomes.exploitAdjudicator ?? "success";
  const verifierExists = outcomes.verifierExists ?? true;
  const count = outcomes.hypotheses ?? 1;

  return {
    async complete(options) {
      const system = options.messages[0]?.content ?? "";

      if (options.model === FAKE_CREDENTIALS.judgeModel) {
        if (system.includes("plausibility_judge")) return judgeReply(plausibility);
        if (system.includes("success_adjudicator")) return judgeReply(adjudicator);
        if (system.includes("exploit_adjudicator")) return judgeReply(exploitAdjudicator);
        if (system.includes("verification_judge")) return judgeReply(verification);
        return judgeReply("inconclusive");
      }

      // The generators (recon, synthesis, verify) run as agent loops, so a reply
      // is the agent envelope. The scripted model answers on the first turn with
      // `{done, result}` — the agent accepts a final answer without any tool round.
      const done = (result: unknown, totalTokens: number) => ({
        content: JSON.stringify({ done: true, result }),
        totalTokens,
      });

      if (options.model === FAKE_CREDENTIALS.verifierModel) {
        // Independent verifier agent.
        return done({ exists: verifierExists, reasoning: "independent read of the code" }, 6);
      }

      if (options.model === FAKE_CREDENTIALS.attackerModel) {
        if (system.includes("reconnaissance stage")) {
          return done(
            {
              summary: "A small web service with an auth module.",
              surface: [
                { area: "authentication", files: ["src/auth.js"], why: "handles login", exploitability: 5, impact: 5 },
              ],
            },
            40,
          );
        }
        // Checked before the generic "attacker brain" match below, since the
        // exploit stage's system prompt also contains that phrase.
        if (system.includes("now proving a hypothesis")) {
          return done(
            provable
              ? {
                  provable: true,
                  poc: "GET /api/profile?userId=<victim-id> with the attacker's own session cookie",
                  trace: ["src/auth.js:10"],
                  impact: "returns the victim's profile data to the attacker",
                  confidence: "high",
                }
              : { provable: false },
            30,
          );
        }
        if (system.includes("attacker brain")) {
          const hypotheses = Array.from({ length: count }, (_, i) => ({
            title: `Scripted flaw ${i + 1}`,
            class: "B",
            severity: "high",
            component: "authentication",
            files: ["src/auth.js:10"],
            mechanism: "trusts a client-supplied identifier without a server-side check",
            impact: "one user can act as another",
            evidence: "const userId = req.query.userId;",
          }));
          return done({ hypotheses }, 60);
        }
        if (system.includes("remediation")) {
          // root_cause is a single-shot callJson, not an agent — plain JSON.
          return {
            content: JSON.stringify({ remediation: "Derive the identifier from the authenticated session." }),
            totalTokens: 20,
          };
        }
      }

      throw new Error(`unscripted model call for ${options.model}`);
    },
  };
}

/** A `fetch` standing in for a (future) live target, always answering 200. */
export const fakeTargetFetch: typeof fetch = (async () =>
  new Response(null, { status: 200, statusText: "OK", headers: { "x-fake": "1" } })) as typeof fetch;
