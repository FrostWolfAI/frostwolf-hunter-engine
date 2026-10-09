/**
 * The red-teaming pipeline — agentic, white-box novel-vulnerability discovery.
 *
 * The generators (recon, synthesis, independent verification) are real agents: the
 * model drives, calling tools — list_dir, read_file, search, and, where available,
 * bash (in the sandbox) and web_search — to explore the code, follow data flows
 * across files, and ground its reasoning, under a step and token budget. The judges
 * (plausibility, success, verification) stay single-shot and low-temperature: a
 * generator explores and proposes; a judge on a *different* model rules once, and a
 * flaw is promoted only after N independent reproductions agree.
 *
 * Nothing here executes the target's code except through the `bash` tool, which runs
 * only inside the isolated container (disabled until one is configured). A run that
 * confirms nothing promotes nothing.
 */

import { account } from "../agent.js";
import { constructProof, type ExploitProof } from "../exploit.js";
import { parseLooseJson } from "../json.js";
import { readRepoFile } from "../repo-read.js";
import { scopeRepo } from "../scope.js";
import type { RunContext, Stage } from "../state-machine.js";
import type { Finding, Hypothesis } from "../types.js";

const RECON_STEPS = 10;
const VERIFY_STEPS = 8;
const MAX_HYPOTHESES = 12;
const MAX_QUEUED = 12;  // validate everything plausible, not just the top few
/** Synthesis walks the ranked surface areas, a focused pass each, for real coverage. */
const MAX_AREAS = 6;
const PER_AREA_STEPS = 9;
const PER_AREA_HYPOTHESES = 3;
const MAX_VALIDATE_BYTES = 60 * 1024;

type NoveltyClass = "A" | "B" | "C" | "D";
type Severity = Finding["severity"];

interface RichHypothesis {
  readonly code: string;
  readonly title: string;
  readonly novelty_class: NoveltyClass;
  readonly severity: Severity;
  readonly component: string;
  readonly files: readonly string[];
  readonly mechanism: string;
  readonly impact: string;
  readonly evidence: string;
  /** Set once `exploitStage` gets a judge-adjudicated construction past it. */
  readonly proof?: ExploitProof;
}

const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];
const CLASSES: readonly NoveltyClass[] = ["A", "B", "C", "D"];

function clearedVerdict(v: { readonly verdict: string }): boolean {
  return v.verdict === "success" || v.verdict === "partial";
}

function asSeverity(value: unknown): Severity {
  return SEVERITIES.find((s) => s === value) ?? "medium";
}
function asClass(value: unknown): NoveltyClass {
  return CLASSES.find((c) => c === value) ?? "C";
}
function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** One single-shot model call expected to return JSON. Null on any failure. */
async function callJson<T>(
  ctx: RunContext,
  model: string,
  stage: string,
  system: string,
  user: string,
  temperature: number,
): Promise<T | null> {
  try {
    const result = await ctx.client.complete({
      model,
      temperature,
      json: true,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user },
      ],
    });
    account(ctx, result.totalTokens);
    const parsed = parseLooseJson(result.content);
    if (parsed === null) {
      throw new Error("no JSON object in reply");
    }
    return parsed as T;
  } catch (error) {
    ctx.emit("warn", stage, `model call did not return usable JSON: ${errText(error)}`);
    return null;
  }
}

function errText(error: unknown): string {
  return error instanceof Error ? error.message : "unknown error";
}

/** Read the files a hypothesis points at, from the checkout, under a byte cap. */
async function gatherReferenced(ctx: RunContext, files: readonly string[]): Promise<string> {
  if (ctx.repoDir === null) {
    return "";
  }
  const blocks: string[] = [];
  let total = 0;
  for (const ref of files.slice(0, 8)) {
    const path = ref.split(":")[0]!;
    const content = await readRepoFile(ctx.repoDir, path);
    if (content === null) {
      continue;
    }
    const block = `\n--- ${path} ---\n${content}\n`;
    if (total + block.length > MAX_VALIDATE_BYTES) {
      break;
    }
    blocks.push(block);
    total += block.length;
  }
  return blocks.join("");
}

// --- Stage 0 — Intake & scope lock -----------------------------------------

const intake: Stage = {
  name: "intake",
  async run(ctx) {
    const repo = scopeRepo(ctx.job);
    if (repo === null) {
      return { ok: false, reason: "no repository in scope: nothing to analyse" };
    }
    if (ctx.repoDir === null) {
      return { ok: false, reason: "repository was not cloned (clone failed or was refused)" };
    }
    ctx.emit("info", "intake", `scope locked to repository ${repo}`);
    return { ok: true };
  },
};

// --- Stage 1 — Recon & threat model (agentic) ------------------------------

interface ThreatModel {
  readonly summary: string;
  readonly surface: ReadonlyArray<{
    readonly area: string;
    readonly files: readonly string[];
    readonly why: string;
    readonly exploitability?: number;
    readonly impact?: number;
  }>;
}

const recon: Stage = {
  name: "recon",
  async run(ctx) {
    ctx.emit("info", "recon", "exploring the repository to build a threat model");
    const model = await ctx.explore<ThreatModel>({
      model: ctx.models.attackerModel,
      stage: "recon",
      maxSteps: RECON_STEPS,
      temperature: 0.4,
      system:
        "You are the reconnaissance stage of an authorized white-box security review of a " +
        "codebase whose owner requested this assessment. Explore the repository with the tools, " +
        "then produce a threat model. Focus on trust boundaries, authn/authz, request handling, " +
        "data access, multi-tenant isolation, and any AI/agent/tool surface. Your final result " +
        'MUST be {"summary": one paragraph, "surface": [{"area": short name, "files": [real repo ' +
        'paths], "why": why it is security-relevant, "exploitability": 1-5, "impact": 1-5}]}.',
      task: "Start by listing the repository root, then read and search your way to a threat model.",
    });

    if (model === null || !Array.isArray(model.surface)) {
      ctx.emit("warn", "recon", "could not build a threat model; synthesis will explore from scratch");
      ctx.scratch.threatModel = { summary: "", surface: [] } satisfies ThreatModel;
      return { ok: true };
    }
    ctx.scratch.threatModel = model;
    const ranked = [...model.surface].sort(
      (a, b) => (b.exploitability ?? 0) * (b.impact ?? 0) - (a.exploitability ?? 0) * (a.impact ?? 0),
    );
    ctx.emit(
      "info",
      "recon",
      `threat model built: ${ranked.length} surface areas` +
        (ranked.length > 0 ? `, top: ${ranked.slice(0, 3).map((a) => a.area).join(", ")}` : ""),
    );
    return { ok: true };
  },
};

// --- Stage 2 — Attack synthesis (agentic) ----------------------------------

interface RawHypothesis {
  readonly title?: string;
  readonly class?: string;
  readonly severity?: string;
  readonly component?: string;
  readonly files?: unknown;
  readonly mechanism?: string;
  readonly impact?: string;
  readonly evidence?: string;
}

const synthesis: Stage = {
  name: "synthesis",
  async run(ctx) {
    const threatModel = ctx.scratch.threatModel as ThreatModel | undefined;
    const areas = [...(threatModel?.surface ?? [])]
      .sort((a, b) => (b.exploitability ?? 0) * (b.impact ?? 0) - (a.exploitability ?? 0) * (a.impact ?? 0))
      .slice(0, MAX_AREAS);

    // Walk each ranked surface area with its own focused pass, so one run covers
    // the whole surface instead of whatever a single shot happened to look at.
    const focuses: Array<ThreatModel["surface"][number] | null> = areas.length > 0 ? areas : [null];
    ctx.emit(
      "info",
      "synthesis",
      areas.length > 0 ? `probing ${areas.length} surface areas` : "hunting for grounded vulnerabilities",
    );

    const system =
      "You are the attacker brain in an authorized white-box review. Use the tools to read code and " +
      "follow data flows across files, then report concrete architecture- or logic-level " +
      "vulnerabilities in THIS code — the kind that reach production and have no public CVE: path " +
      "traversal, command/argument injection, broken multi-tenant isolation, trusted client-supplied " +
      "claims, authorization/approval bypasses, SSRF, insecure direct object references, unsafe " +
      "tool/agent capabilities, secret/credential exposure. Do NOT report known-CVE dependency issues " +
      "or generic nits. Ground each in specific lines you actually read. Your final result MUST be " +
      `{"hypotheses": [{"title", "class": "A|B|C|D", "severity": "critical|high|medium|low", ` +
      '"component", "files": ["path:line"], "mechanism", "impact", "evidence": the exact code}]} ' +
      `with at most ${PER_AREA_HYPOTHESES} entries; use an empty list if this area has no real flaw.`;

    const raw: RawHypothesis[] = [];
    const seen = new Set<string>();
    for (const area of focuses) {
      if (raw.length >= MAX_HYPOTHESES) {
        break;
      }
      if (ctx.budget.exceeded()) {
        ctx.emit("warn", "synthesis", "token budget reached; stopping synthesis early");
        break;
      }
      const proposed = await ctx.explore<{ hypotheses?: RawHypothesis[] }>({
        model: ctx.models.attackerModel,
        stage: "synthesis",
        maxSteps: PER_AREA_STEPS,
        temperature: 0.8,
        system,
        task:
          area === null
            ? `Threat model:\n${JSON.stringify(threatModel ?? {})}\n\nInvestigate and report.`
            : `Focus on this attack surface: "${area.area}" — ${area.why}\n` +
              `Start from these files: ${(area.files ?? []).join(", ")}\n` +
              "Read them and anything they call, then report vulnerabilities in THIS area.",
      });
      for (const h of proposed?.hypotheses ?? []) {
        const key = (typeof h.title === "string" ? h.title : "").trim().toLowerCase();
        if (key.length === 0 || seen.has(key)) {
          continue;
        }
        seen.add(key);
        raw.push(h);
        if (raw.length >= MAX_HYPOTHESES) {
          break;
        }
      }
    }

    if (raw.length === 0) {
      ctx.emit("info", "synthesis", "no grounded hypotheses found");
      return { ok: true };
    }

    const clearedList: RichHypothesis[] = [];
    let index = 0;
    for (const item of raw) {
      if (typeof item.title !== "string" || typeof item.mechanism !== "string") {
        continue;
      }
      index += 1;
      const rich: RichHypothesis = {
        code: `H-${String(index).padStart(3, "0")}`,
        title: item.title,
        novelty_class: asClass(item.class),
        severity: asSeverity(item.severity),
        component: typeof item.component === "string" ? item.component : "unknown",
        files: asStringArray(item.files),
        mechanism: item.mechanism,
        impact: typeof item.impact === "string" ? item.impact : "",
        evidence: typeof item.evidence === "string" ? item.evidence : "",
      };
      const lean: Hypothesis = {
        code: rich.code,
        target: rich.component,
        predicted_class: rich.novelty_class,
        rationale: rich.title,
      };
      ctx.hypothesis(lean);
      ctx.hypothesisStatus(rich.code, "queued");

      const judged = await ctx.judge(
        "plausibility_judge",
        "Is this a real, grounded, production-relevant vulnerability worth validating against the " +
          "code — not speculative, not a generic nit, not a known-CVE dependency issue?",
        `${JSON.stringify({ title: rich.title, mechanism: rich.mechanism, impact: rich.impact })}\n\n` +
          `Cited code:\n${rich.evidence}`,
      );
      ctx.verdict("plausibility_judge", rich.code, judged.verdict);
      account(ctx, judged.totalTokens);

      if (clearedVerdict(judged.verdict)) {
        clearedList.push(rich);
      } else {
        ctx.hypothesisStatus(rich.code, "dropped");
      }
    }

    const order: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    clearedList.sort((a, b) => order[a.severity] - order[b.severity]);
    ctx.scratch.cleared = clearedList.slice(0, MAX_QUEUED);
    ctx.emit(
      "info",
      "synthesis",
      `${raw.length} proposed, ${clearedList.length} cleared, ` +
        `${(ctx.scratch.cleared as RichHypothesis[]).length} queued for validation`,
    );
    return { ok: true };
  },
};

// --- Stage 3 — Validate (adjudicate against the real code) ------------------

const validate: Stage = {
  name: "validate",
  async run(ctx) {
    const cleared = (ctx.scratch.cleared as RichHypothesis[] | undefined) ?? [];
    if (cleared.length === 0) {
      ctx.emit("info", "validate", "nothing cleared to validate");
      return { ok: true };
    }

    const confirmed: RichHypothesis[] = [];
    for (const h of cleared) {
      ctx.hypothesisStatus(h.code, "verifying");
      const code = await gatherReferenced(ctx, h.files);
      if (code.length === 0) {
        ctx.hypothesisStatus(h.code, "falsified");
        ctx.emit("warn", "validate", `${h.code}: referenced files not found`);
        continue;
      }
      const judged = await ctx.judge(
        "success_adjudicator",
        `Given the ACTUAL source below, does it genuinely exhibit this vulnerability? Rule success ` +
          `only if specific lines make it exploitable; fail if the code does not have the flaw.\n\n` +
          `Claim: ${h.title}\nMechanism: ${h.mechanism}`,
        `Source:\n${code}`,
      );
      ctx.verdict("success_adjudicator", h.code, judged.verdict);
      account(ctx, judged.totalTokens);
      if (clearedVerdict(judged.verdict)) {
        confirmed.push(h);
        ctx.emit("info", "validate", `${h.code} confirmed against the code: ${h.title}`);
      } else {
        ctx.hypothesisStatus(h.code, "falsified");
        ctx.emit("info", "validate", `${h.code} not borne out by the code`);
      }
    }
    ctx.scratch.confirmed = confirmed;
    return { ok: true };
  },
};

// --- Stage 3b — Proof of impact (construct, then adjudicate) ----------------
//
// `validate` ruled the flaw is real against the cited code. This asks a harder
// question: could an attacker actually trigger it, and what happens if they do.
// The attacker model constructs a concrete input and traces it through the real
// code (`constructProof`, in `exploit.ts`); a judge then rules on that specific
// construction, not the underlying claim validate already settled. A hypothesis
// that cannot be turned into a concrete demonstration is dropped here rather than
// carried forward on the strength of the claim alone.

const exploitStage: Stage = {
  name: "exploit",
  async run(ctx) {
    const confirmed = (ctx.scratch.confirmed as RichHypothesis[] | undefined) ?? [];
    if (confirmed.length === 0) {
      ctx.emit("info", "exploit", "nothing confirmed to prove impact for");
      return { ok: true };
    }

    const exploited: RichHypothesis[] = [];
    for (const h of confirmed) {
      if (ctx.budget.exceeded()) {
        ctx.emit("warn", "exploit", "token budget reached; stopping proof construction early");
        break;
      }

      ctx.hypothesisStatus(h.code, "exploiting");
      const code = await gatherReferenced(ctx, h.files);
      const proof = await constructProof(ctx, h, code);
      if (proof === null) {
        ctx.hypothesisStatus(h.code, "falsified");
        ctx.emit("info", "exploit", `${h.code}: attacker brain could not construct a concrete proof`);
        continue;
      }

      const judged = await ctx.judge(
        "exploit_adjudicator",
        "A different judge already confirmed this flaw is real in the code. Rule on THIS specific " +
          "construction: is the attacker input concrete, and does it actually traverse the cited " +
          "code to the claimed impact — not hand-waved, not a restatement of the mechanism?",
        `Claim: ${h.title}\nMechanism: ${h.mechanism}\n\n` +
          `Constructed proof:\n${JSON.stringify(proof)}\n\nCode:\n${code}`,
      );
      ctx.verdict("exploit_adjudicator", h.code, judged.verdict);
      account(ctx, judged.totalTokens);

      if (clearedVerdict(judged.verdict)) {
        exploited.push({ ...h, proof });
        ctx.hypothesisStatus(h.code, "exploited");
        ctx.emit("info", "exploit", `${h.code} proven (${proof.confidence} confidence): ${proof.poc.slice(0, 200)}`);
      } else {
        ctx.hypothesisStatus(h.code, "falsified");
        ctx.emit("info", "exploit", `${h.code}: construction did not hold up to adjudication`);
      }
    }

    ctx.scratch.exploited = exploited;
    return { ok: true };
  },
};

// --- Stage 4 — Independent verification (agentic re-derivation) -------------

const verify: Stage = {
  name: "verify",
  async run(ctx) {
    // Verify the hypotheses that were successfully exploited
    const exploited = (ctx.scratch.exploited as RichHypothesis[] | undefined) ?? [];
    if (exploited.length === 0) {
      ctx.emit("info", "verify", "nothing exploited to verify independently");
      return { ok: true };
    }

    const n = Math.max(1, ctx.models.verifyN);
    const verified: Array<{ h: RichHypothesis; reproRatio: string }> = [];

    for (const h of exploited) {
      let successes = 0;
      for (let attempt = 1; attempt <= n; attempt++) {
        if (ctx.budget.exceeded()) {
          ctx.emit("warn", "verify", "token budget exhausted; stopping verification");
          break;
        }
        // The verifier model explores independently (its own tool run) and is told
        // only the claim title, never the attacker's reasoning.
        const independent = await ctx.explore<{ exists?: boolean; reasoning?: string }>({
          model: ctx.models.verifierModel,
          stage: "verify",
          maxSteps: VERIFY_STEPS,
          temperature: 0.2,
          system:
            "You are an independent reviewer. Using the tools, decide for yourself, only from the " +
            'code, whether the named vulnerability genuinely exists. Final result MUST be ' +
            '{"exists": true|false, "reasoning": cite the specific lines or explain why not}.',
          task: `Vulnerability to check: ${h.title}\nComponent: ${h.component}\nFiles to start from: ${h.files.join(", ")}`,
        });

        const determination = independent ?? { exists: false, reasoning: "no usable answer" };
        const judged = await ctx.judge(
          "verification_judge",
          `Independent reproduction ${attempt}/${n}. Does the reviewer's determination, grounded in ` +
            `the code, confirm "${h.title}" is real?`,
          `Reviewer determination: ${JSON.stringify(determination)}`,
        );
        ctx.verdict("verification_judge", h.code, judged.verdict);
        account(ctx, judged.totalTokens);
        if (determination.exists === true && clearedVerdict(judged.verdict)) {
          successes += 1;
        }
      }

      const threshold = Math.ceil(n / 2);
      ctx.emit("info", "verify", `${h.code} reproduced ${successes}/${n} (need ${threshold})`);
      if (successes >= threshold) {
        ctx.hypothesisStatus(h.code, "confirmed");
        verified.push({ h, reproRatio: `${successes}/${n}` });
      } else {
        ctx.hypothesisStatus(h.code, "falsified");
      }
    }
    ctx.scratch.verified = verified;
    return { ok: true };
  },
};

// --- Stage 6 — Root-cause & remediation ------------------------------------

interface Verified {
  readonly h: RichHypothesis;
  readonly reproRatio: string;
  remediation?: string;
}

const rootCause: Stage = {
  name: "root_cause",
  async run(ctx) {
    const verified = (ctx.scratch.verified as Verified[] | undefined) ?? [];
    if (verified.length === 0) {
      ctx.emit("info", "root_cause", "nothing verified to remediate");
      return { ok: true };
    }
    for (const v of verified) {
      const code = await gatherReferenced(ctx, v.h.files);
      const fix = await callJson<{ remediation?: string }>(
        ctx,
        ctx.models.attackerModel,
        "root_cause",
        "Given the vulnerability and its code, write the precise remediation: what to change and why " +
          'it closes the flaw without breaking behaviour. Answer as {"remediation": the guidance}.',
        `Vulnerability: ${v.h.title}\nMechanism: ${v.h.mechanism}\n\nSource:\n${code}`,
        0.3,
      );
      v.remediation = fix?.remediation ?? "See mechanism; apply standard remediation for this class.";
      ctx.emit("info", "root_cause", `${v.h.code}: remediation drafted`);
    }
    ctx.scratch.verified = verified;
    return { ok: true };
  },
};

// --- Stage 7 — Report & writeback ------------------------------------------

const report: Stage = {
  name: "report",
  async run(ctx) {
    const verified = (ctx.scratch.verified as Verified[] | undefined) ?? [];
    if (verified.length === 0) {
      ctx.emit("info", "report", "nothing confirmed this run; no finding promoted");
      return { ok: true };
    }
    for (const v of verified) {
      ctx.emit("info", "report", `promoting ${v.h.code}: ${v.h.title}`);
      const proof = v.h.proof;
      const evidence =
        proof === undefined
          ? v.h.evidence
          : `${v.h.evidence}\n\n--- Proof of impact (${proof.confidence} confidence) ---\n` +
            `Attacker input: ${proof.poc}\nCode path: ${proof.trace.join(" → ") || "(not cited)"}\n` +
            `Impact: ${proof.impact}`;
      ctx.promote({
        title: v.h.title,
        severity: v.h.severity,
        novelty_class: v.h.novelty_class,
        repro_ratio: v.reproRatio,
        hypothesis_code: v.h.code,
        mechanism: v.h.mechanism,
        location: v.h.files.join(", "),
        remediation: v.remediation ?? "",
        evidence,
      });
    }
    return { ok: true };
  },
};

export const STAGES: readonly Stage[] = [
  intake,
  recon,
  synthesis,
  validate,
  exploitStage,
  verify,
  rootCause,
  report,
];
