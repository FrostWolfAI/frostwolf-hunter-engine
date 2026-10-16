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
 * only inside the isolated container (always on; the sandbox is never disabled). A run
 * that confirms nothing promotes nothing.
 */

import { account } from "../agent.js";
import { type CvssResult, fallbackCvssForSeverity, parseCvss } from "../cvss.js";
import { constructProof, type ExploitProof } from "../exploit.js";
import { parseLooseJson } from "../json.js";
import { readRepoFile } from "../repo-read.js";
import { scopeRepo } from "../scope.js";
import type { RunContext, Stage } from "../state-machine.js";
import type { Finding, Hypothesis } from "../types.js";

/** A positive integer from the environment, or the default. Lets a run trade depth
 * for speed/cost (e.g. HUNT_MAX_QUEUED=3 for a fast pass) without changing the
 * thorough defaults. */
function intEnv(name: string, fallback: number): number {
  const n = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
}

const RECON_STEPS = 10;
const VERIFY_STEPS = 8;
const MAX_HYPOTHESES = intEnv("HUNT_MAX_HYPOTHESES", 12);
/** How many cleared hypotheses go through validate -> exploit -> verify (the costly
 * deep stages). With the judge skipped nothing prunes, so this is the main lever. */
const MAX_QUEUED = intEnv("HUNT_MAX_QUEUED", 12);
/** Synthesis walks the ranked surface areas, a focused pass each, for real coverage. */
const MAX_AREAS = intEnv("HUNT_MAX_AREAS", 6);
const PER_AREA_STEPS = 9;
const PER_AREA_HYPOTHESES = intEnv("HUNT_PER_AREA", 3);
const MAX_VALIDATE_BYTES = 60 * 1024;

function isBountyMode(ctx: RunContext): boolean {
  return ctx.job.depth === "bounty" || ctx.job.policy?.mode === "bounty";
}

function is100PercentValidated(reproRatio: string): boolean {
  const m = /^(\d+)\/(\d+)$/.exec(reproRatio.trim());
  if (!m) {
    return false;
  }
  const num = Number.parseInt(m[1]!, 10);
  const den = Number.parseInt(m[2]!, 10);
  return den > 0 && num === den;
}

type NoveltyClass = "A" | "B" | "C" | "D";
type Severity = Finding["severity"];

interface RichHypothesis {
  readonly code: string;
  readonly title: string;
  readonly novelty_class: NoveltyClass;
  readonly severity: Severity;
  readonly cvss: CvssResult;
  readonly cwe?: string | undefined;
  readonly owasp?: string | undefined;
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
async function gatherReferenced(
  ctx: RunContext,
  files: readonly string[],
  maxBytes = MAX_VALIDATE_BYTES,
): Promise<string> {
  if (ctx.repoDir === null) {
    return "";
  }
  const blocks: string[] = [];
  let total = 0;
  for (const ref of files.slice(0, 10)) {
    const path = ref.split(":")[0]!;
    const content = await readRepoFile(ctx.repoDir, path);
    if (content === null) {
      continue;
    }
    const block = `\n--- ${path} ---\n${content}\n`;
    if (total + block.length > maxBytes) {
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
    const bounty = isBountyMode(ctx);
    ctx.emit(
      "info",
      "recon",
      bounty
        ? "exploring the repository to build a threat model (bounty mode: deep untrusted-entrypoint analysis)"
        : "exploring the repository to build a threat model",
    );
    const model = await ctx.explore<ThreatModel>({
      model: ctx.models.attackerModel,
      stage: "recon",
      maxSteps: bounty ? RECON_STEPS * 2 : RECON_STEPS,
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
  readonly cvss?: unknown;
  readonly cwe?: string;
  readonly owasp?: string;
  readonly component?: string;
  readonly files?: unknown;
  readonly mechanism?: string;
  readonly impact?: string;
  readonly evidence?: string;
}

const synthesis: Stage = {
  name: "synthesis",
  async run(ctx) {
    const bounty = isBountyMode(ctx);
    const maxAreas = bounty ? Math.max(MAX_AREAS, 8) : MAX_AREAS;
    const perAreaSteps = bounty ? Math.max(PER_AREA_STEPS, 16) : PER_AREA_STEPS;
    const threatModel = ctx.scratch.threatModel as ThreatModel | undefined;
    const areas = [...(threatModel?.surface ?? [])]
      .sort((a, b) => (b.exploitability ?? 0) * (b.impact ?? 0) - (a.exploitability ?? 0) * (a.impact ?? 0))
      .slice(0, maxAreas);

    // Walk each ranked surface area with its own focused pass, so one run covers
    // the whole surface instead of whatever a single shot happened to look at.
    const focuses: Array<ThreatModel["surface"][number] | null> = areas.length > 0 ? areas : [null];
    ctx.emit(
      "info",
      "synthesis",
      areas.length > 0 ? `probing ${areas.length} surface areas` : "hunting for grounded vulnerabilities",
    );

    const bountyGuidance = bounty
      ? " BOUNTY MODE: Only report vulnerabilities eligible for a HackerOne/Bugcrowd payout with a " +
        "concrete untrusted source-to-sink path (RCE, command/argument injection, SSRF, path traversal, " +
        "arbitrary file read/write, SQLi, SSTI, authn/authz bypass, IDOR, cross-tenant leak, HTML/script " +
        "injection in rendered sinks, or credential disclosure). Strictly EXCLUDE defense-in-depth " +
        "hardening, missing rate limits, missing resource quotas/NetworkPolicies, self-XSS, or issues " +
        "requiring pre-existing administrator compromise."
      : "";

    const system =
      "You are the attacker brain in an authorized white-box review. Use the tools to read code and " +
      "follow data flows across files, then report concrete architecture- or logic-level " +
      "vulnerabilities in THIS code — the kind that reach production and have no public CVE: path " +
      "traversal, command/argument injection, broken multi-tenant isolation, trusted client-supplied " +
      "claims, authorization/approval bypasses, SSRF, insecure direct object references, unsafe " +
      "tool/agent capabilities, secret/credential exposure. Do NOT report known-CVE dependency issues " +
      "or generic nits. Ground each in specific lines you actually read." +
      bountyGuidance +
      " Score severity using the Common Vulnerability Scoring System (CVSS v3.1) base vector " +
      "(e.g. \"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N\"). Your final result MUST be " +
      `{"hypotheses": [{"title", "class": "A|B|C|D", "severity": "critical|high|medium|low", ` +
      '"cvss": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...", "cwe": "CWE-...", "owasp": "A01:2021-...", ' +
      '"component", "files": ["path:line"], "mechanism", "impact", "evidence": the exact code}]} ' +
      `with at most ${PER_AREA_HYPOTHESES} entries; use an empty list if this area has no real flaw.`;

    const raw: RawHypothesis[] = [];
    const seen = new Set<string>();
    for (const area of focuses) {
      if (raw.length >= MAX_HYPOTHESES) {
        break;
      }
      const proposed = await ctx.explore<{ hypotheses?: RawHypothesis[] }>({
        model: ctx.models.attackerModel,
        stage: "synthesis",
        maxSteps: perAreaSteps,
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
      const fallbackSev = asSeverity(item.severity);
      const cvss = parseCvss(item.cvss) ?? fallbackCvssForSeverity(fallbackSev);
      const rich: RichHypothesis = {
        code: `H-${String(index).padStart(3, "0")}`,
        title: item.title,
        novelty_class: asClass(item.class),
        severity: cvss.severity,
        cvss,
        cwe: typeof item.cwe === "string" && item.cwe.trim().length > 0 ? item.cwe.trim() : undefined,
        owasp: typeof item.owasp === "string" && item.owasp.trim().length > 0 ? item.owasp.trim() : undefined,
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
        bounty
          ? "Is this a directly exploitable, bounty-eligible vulnerability with a concrete untrusted " +
              "source-to-sink path — NOT defense-in-depth, NOT missing rate limits/quotas/NetworkPolicy, " +
              "NOT self-XSS, and NOT requiring pre-existing admin compromise?"
          : "Is this a real, grounded, production-relevant vulnerability worth validating against the " +
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
    clearedList.sort((a, b) => {
      const sevDiff = order[a.severity] - order[b.severity];
      return sevDiff !== 0 ? sevDiff : b.cvss.score - a.cvss.score;
    });
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

    const bounty = isBountyMode(ctx);
    const maxBytes = bounty ? MAX_VALIDATE_BYTES * 3 : MAX_VALIDATE_BYTES;
    const confirmed: RichHypothesis[] = [];
    for (const h of cleared) {
      ctx.hypothesisStatus(h.code, "verifying");
      const code = await gatherReferenced(ctx, h.files, maxBytes);
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

// --- Stage 3b — Proof of impact (best-effort construction) ------------------
//
// `validate` ruled the flaw is real against the cited code. This asks a harder
// question: could an attacker actually trigger it, and what happens if they do.
// The attacker model constructs a concrete input and traces it through the real
// code (`constructProof`, in `exploit.ts`), and the construction is attached to
// the finding when it succeeds.
//
// This stage NEVER gates. Every confirmed hypothesis is carried forward to
// independent verification whether or not a proof was built, so the
// recon → synthesis → validate → verify flow runs end to end every time. A missing
// proof weakens a finding's evidence; it does not drop the finding. (Turning a
// constructed proof into an executed one is the live-exploitation layer tracked in
// HUNTER-STATUS.md; it is not this stage.)

const exploitStage: Stage = {
  name: "exploit",
  async run(ctx) {
    const confirmed = (ctx.scratch.confirmed as RichHypothesis[] | undefined) ?? [];
    if (confirmed.length === 0) {
      ctx.emit("info", "exploit", "nothing confirmed to prove impact for");
      ctx.scratch.exploited = [];
      return { ok: true };
    }

    const bounty = isBountyMode(ctx);
    const maxBytes = bounty ? MAX_VALIDATE_BYTES * 3 : MAX_VALIDATE_BYTES;
    const exploited: RichHypothesis[] = [];
    for (const h of confirmed) {
      ctx.hypothesisStatus(h.code, "exploiting");
      const code = await gatherReferenced(ctx, h.files, maxBytes);
      const proof = await constructProof(ctx, h, code);
      if (proof === null) {
        if (bounty) {
          ctx.hypothesisStatus(h.code, "falsified");
          ctx.emit(
            "info",
            "exploit",
            `${h.code}: bounty mode requires a concrete PoC; dropping hypothesis without proof`,
          );
          continue;
        }
        exploited.push(h);
        ctx.emit("info", "exploit", `${h.code}: no concrete proof constructed; carried forward for verification`);
        continue;
      }
      if (bounty && proof.confidence === "low") {
        ctx.hypothesisStatus(h.code, "falsified");
        ctx.emit(
          "info",
          "exploit",
          `${h.code}: bounty mode requires medium/high PoC confidence (got low); dropping hypothesis`,
        );
        continue;
      }

      exploited.push({ ...h, proof });
      ctx.hypothesisStatus(h.code, "exploited");
      ctx.emit("info", "exploit", `${h.code} proof constructed (${proof.confidence} confidence): ${proof.poc.slice(0, 200)}`);
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

    const bounty = isBountyMode(ctx);
    const n = bounty ? Math.max(2, ctx.models.verifyN) : Math.max(1, ctx.models.verifyN);
    const verifySteps = bounty ? Math.max(VERIFY_STEPS, 12) : VERIFY_STEPS;
    const verified: Array<{ h: RichHypothesis; reproRatio: string }> = [];

    for (const h of exploited) {
      let successes = 0;
      for (let attempt = 1; attempt <= n; attempt++) {
        // The verifier model explores independently (its own tool run) and is told
        // only the claim title, never the attacker's reasoning.
        const independent = await ctx.explore<{ exists?: boolean; reasoning?: string }>({
          model: ctx.models.verifierModel,
          stage: "verify",
          maxSteps: verifySteps,
          temperature: 0.2,
          // A fresh session: the re-derivation must not inherit the shared
          // recon/synthesis/exploit context, or it would not be independent.
          fresh: true,
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

      // Bounty mode requires 100% (n/n) independent verification before promotion.
      const threshold = bounty ? n : Math.ceil(n / 2);
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

interface HackerOneReportDraft {
  readonly summary?: string;
  readonly poc_notes?: string;
  readonly reproduction_steps?: readonly string[];
  readonly preconditions_and_scope?: readonly string[];
  readonly remediation_steps?: readonly string[];
  readonly impact_assessment?: string;
  readonly cvss_vector?: string;
  readonly cvss_score?: number;
}

interface Verified {
  readonly h: RichHypothesis;
  readonly reproRatio: string;
  remediation?: string;
  cvss?: CvssResult;
  h1Report?: HackerOneReportDraft;
  promoted?: boolean;
}

function promoteVerified(ctx: RunContext, v: Verified): void {
  if (v.promoted) {
    return;
  }
  v.promoted = true;
  const cvss = v.cvss ?? v.h.cvss ?? fallbackCvssForSeverity(v.h.severity);
  ctx.emit(
    "info",
    "report",
    `promoting ${v.h.code} (${cvss.severity.toUpperCase()} · CVSS ${cvss.score.toFixed(1)} ${cvss.vector}): ${v.h.title}`,
  );
  const proof = v.h.proof;
  let evidence =
    proof === undefined
      ? v.h.evidence
      : `${v.h.evidence}\n\n--- Proof of impact (${proof.confidence} confidence) ---\n` +
        `Attacker input: ${proof.poc}\nCode path: ${proof.trace.join(" → ") || "(not cited)"}\n` +
        `Impact: ${proof.impact}`;

  evidence +=
    `\n\n--- CVSS v3.1 ---\n` +
    `Vector: ${cvss.vector}\n` +
    `Score: ${cvss.score.toFixed(1)} (${cvss.severity.toUpperCase()})`;

  if (v.h1Report !== undefined && typeof v.h1Report.summary === "string" && v.h1Report.summary.trim().length > 0) {
    const enrichedH1: HackerOneReportDraft = {
      ...v.h1Report,
      cvss_vector: cvss.vector,
      cvss_score: cvss.score,
    };
    evidence += `\n\n--- HackerOne Report (100% Validated) ---\n${JSON.stringify(enrichedH1)}`;
  }

  ctx.promote({
    title: v.h.title,
    severity: cvss.severity,
    novelty_class: v.h.novelty_class,
    ...(v.h.cwe !== undefined ? { cwe: v.h.cwe } : {}),
    ...(v.h.owasp !== undefined ? { owasp: v.h.owasp } : {}),
    repro_ratio: v.reproRatio,
    hypothesis_code: v.h.code,
    mechanism: v.h.mechanism,
    location: v.h.files.join(", "),
    remediation: v.remediation ?? "",
    evidence,
  });
}

const rootCause: Stage = {
  name: "root_cause",
  async run(ctx) {
    const verified = (ctx.scratch.verified as Verified[] | undefined) ?? [];
    if (verified.length === 0) {
      ctx.emit("info", "root_cause", "nothing verified to remediate");
      return { ok: true };
    }
    const bounty = isBountyMode(ctx);
    const maxBytes = bounty ? MAX_VALIDATE_BYTES * 3 : MAX_VALIDATE_BYTES;
    const CONCURRENCY = 3;
    for (let i = 0; i < verified.length; i += CONCURRENCY) {
      const batch = verified.slice(i, i + CONCURRENCY);
      await Promise.all(
        batch.map(async (v) => {
          const code = await gatherReferenced(ctx, v.h.files, maxBytes);
          const validated100 = is100PercentValidated(v.reproRatio);
          const fix = await callJson<{
            remediation?: string;
            cvss?: unknown;
            h1_report?: HackerOneReportDraft;
          }>(
            ctx,
            ctx.models.attackerModel,
            "root_cause",
            "Given the vulnerability and its code, write the precise remediation: what to change and why " +
              "it closes the flaw without breaking behaviour. Also score the vulnerability using the " +
              "Common Vulnerability Scoring System (CVSS v3.1) base vector reflecting its true attack " +
              "vector (AV), attack complexity (AC), privileges required (PR), user interaction (UI), " +
              "scope (S), and confidentiality/integrity/availability impact (C/I/A)." +
              (validated100
                ? " Because this finding reached 100% independent validation, also include a HackerOne-grade " +
                  "bounty submission (`h1_report`) modeled on PortSwigger/HackerOne disclosed reports: " +
                  '{"remediation": "concise remediation", "cvss": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...", ' +
                  '"h1_report": {"summary": "2 paragraphs: exact component/file ' +
                  'and how attacker input reaches the sink without neutralization, followed by confirmation of the full chain and trigger conditions", ' +
                  '"poc_notes": "exact explanation of the PoC payload and why specific tokens/encodings are needed", ' +
                  '"reproduction_steps": ["1. ...", "2. ...", "3. ..."], ' +
                  '"preconditions_and_scope": ["honest bullet on required configuration/actions", "explicit bullet on what is NOT claimed"], ' +
                  '"remediation_steps": ["1. ...", "2. ...", "3. Add regression tests covering ..."], ' +
                  '"impact_assessment": "concrete security consequence + honest CVSS v3.1 severity rationale"}}.'
                : ' Answer as {"remediation": the guidance, "cvss": "CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:..."}.'),
            `Vulnerability: ${v.h.title}\nInitial CVSS: ${v.h.cvss.vector} (${v.h.cvss.score.toFixed(1)} ${v.h.severity})\n` +
              `Files: ${v.h.files.join(", ")}\n` +
              `Mechanism: ${v.h.mechanism}\nImpact: ${v.h.impact}\n` +
              (v.h.proof
                ? `PoC Input: ${v.h.proof.poc}\nTrace: ${v.h.proof.trace.join(" -> ")}\n`
                : "") +
              `\nSource:\n${code}`,
            0.3,
          );
          v.remediation = fix?.remediation ?? "See mechanism; apply standard remediation for this class.";
          const refinedCvss =
            parseCvss(fix?.cvss) ??
            parseCvss(fix?.h1_report?.cvss_vector) ??
            v.h.cvss;
          v.cvss = refinedCvss;
          if (fix?.h1_report && typeof fix.h1_report === "object") {
            v.h1Report = fix.h1_report;
          }
          ctx.emit(
            "info",
            "root_cause",
            `${v.h.code}: remediation & CVSS ${refinedCvss.score.toFixed(1)} (${refinedCvss.vector})${v.h1Report ? " & HackerOne report" : ""} drafted`,
          );
          promoteVerified(ctx, v);
        }),
      );
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
      promoteVerified(ctx, v);
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
