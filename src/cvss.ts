/**
 * Deterministic Common Vulnerability Scoring System (CVSS v3.1) calculator.
 *
 * Implements the official FIRST CVSS v3.1 Base Score specification so that
 * severity buckets (`critical`, `high`, `medium`, `low`), numeric scores
 * (`0.0 - 10.0`), and vector strings (`CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...`)
 * are computed mathematically from base metrics rather than guessed qualitatively.
 */

import type { Finding } from "./types.js";

export type Severity = Finding["severity"];

export type AttackVector = "N" | "A" | "L" | "P";
export type AttackComplexity = "L" | "H";
export type PrivilegesRequired = "N" | "L" | "H";
export type UserInteraction = "N" | "R";
export type ScopeMetric = "U" | "C";
export type ImpactMetric = "N" | "L" | "H";

export interface CvssMetrics {
  readonly AV: AttackVector;
  readonly AC: AttackComplexity;
  readonly PR: PrivilegesRequired;
  readonly UI: UserInteraction;
  readonly S: ScopeMetric;
  readonly C: ImpactMetric;
  readonly I: ImpactMetric;
  readonly A: ImpactMetric;
}

export interface CvssResult {
  readonly version: "3.1";
  readonly vector: string;
  readonly score: number;
  readonly severity: Severity;
  readonly metrics: CvssMetrics;
}

const AV_WEIGHTS: Readonly<Record<AttackVector, number>> = {
  N: 0.85,
  A: 0.62,
  L: 0.55,
  P: 0.2,
};

const AC_WEIGHTS: Readonly<Record<AttackComplexity, number>> = {
  L: 0.77,
  H: 0.44,
};

const PR_WEIGHTS_UNCHANGED: Readonly<Record<PrivilegesRequired, number>> = {
  N: 0.85,
  L: 0.62,
  H: 0.27,
};

const PR_WEIGHTS_CHANGED: Readonly<Record<PrivilegesRequired, number>> = {
  N: 0.85,
  L: 0.68,
  H: 0.5,
};

const UI_WEIGHTS: Readonly<Record<UserInteraction, number>> = {
  N: 0.85,
  R: 0.62,
};

const IMPACT_WEIGHTS: Readonly<Record<ImpactMetric, number>> = {
  H: 0.56,
  L: 0.22,
  N: 0.0,
};

/**
 * FIRST CVSS v3.1 `Roundup` function:
 * Rounds up to the nearest tenth of a point using integer arithmetic
 * (`round(x * 100000)`) to avoid IEEE-754 floating-point drift.
 */
export function cvssRoundUp(input: number): number {
  const intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) {
    return intInput / 100000;
  }
  return (Math.floor(intInput / 10000) + 1) / 10;
}

/** Map a numeric CVSS v3.1 base score (`0.0 - 10.0`) to a FrostWolf `Severity` bucket. */
export function scoreToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

/** Format a canonical CVSS v3.1 vector string from base metrics. */
export function formatCvssVector(m: CvssMetrics): string {
  return `CVSS:3.1/AV:${m.AV}/AC:${m.AC}/PR:${m.PR}/UI:${m.UI}/S:${m.S}/C:${m.C}/I:${m.I}/A:${m.A}`;
}

/** Compute the exact CVSS v3.1 score, severity, and canonical vector from metrics. */
export function calculateCvss(metrics: CvssMetrics): CvssResult {
  const av = AV_WEIGHTS[metrics.AV];
  const ac = AC_WEIGHTS[metrics.AC];
  const pr =
    metrics.S === "C"
      ? PR_WEIGHTS_CHANGED[metrics.PR]
      : PR_WEIGHTS_UNCHANGED[metrics.PR];
  const ui = UI_WEIGHTS[metrics.UI];

  const c = IMPACT_WEIGHTS[metrics.C];
  const i = IMPACT_WEIGHTS[metrics.I];
  const a = IMPACT_WEIGHTS[metrics.A];

  const iss = 1 - (1 - c) * (1 - i) * (1 - a);

  const impact =
    metrics.S === "U"
      ? 6.42 * iss
      : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);

  const exploitability = 8.22 * av * ac * pr * ui;

  let score: number;
  if (impact <= 0) {
    score = 0.0;
  } else if (metrics.S === "U") {
    score = cvssRoundUp(Math.min(impact + exploitability, 10));
  } else {
    score = cvssRoundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  return {
    version: "3.1",
    vector: formatCvssVector(metrics),
    score,
    severity: scoreToSeverity(score),
    metrics,
  };
}

function asEnum<T extends string>(val: unknown, allowed: readonly T[]): T | null {
  if (typeof val !== "string") return null;
  const upper = val.trim().toUpperCase();
  return allowed.find((item) => item === upper) ?? null;
}

/**
 * Parse a CVSS v3.1 vector string (`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`)
 * or a loose metrics object (`{ AV: "N", AC: "L", ... }`) into a `CvssResult`.
 * Returns `null` when any required metric is missing or invalid.
 */
export function parseCvss(input: unknown): CvssResult | null {
  if (typeof input === "string") {
    const trimmed = input.trim();
    const parts = trimmed.replace(/^CVSS:3\.[01]\//i, "").split("/");
    const map: Record<string, string> = {};
    for (const part of parts) {
      const [k, v] = part.split(":");
      if (k && v) {
        map[k.trim().toUpperCase()] = v.trim().toUpperCase();
      }
    }
    return parseCvss(map);
  }

  if (input === null || typeof input !== "object") {
    return null;
  }

  const raw = input as Record<string, unknown>;
  const get = (key: string): unknown =>
    raw[key] ?? raw[key.toLowerCase()] ?? raw[key.toUpperCase()];

  // Allow nested `{ vector: "CVSS:3.1/..." }` or `{ metrics: { ... } }`
  if (typeof raw.vector === "string") {
    const fromVec = parseCvss(raw.vector);
    if (fromVec !== null) return fromVec;
  }
  if (raw.metrics && typeof raw.metrics === "object") {
    const fromMetrics = parseCvss(raw.metrics);
    if (fromMetrics !== null) return fromMetrics;
  }

  const AV = asEnum(get("AV"), ["N", "A", "L", "P"] as const);
  const AC = asEnum(get("AC"), ["L", "H"] as const);
  const PR = asEnum(get("PR"), ["N", "L", "H"] as const);
  const UI = asEnum(get("UI"), ["N", "R"] as const);
  const S = asEnum(get("S"), ["U", "C"] as const);
  const C = asEnum(get("C"), ["N", "L", "H"] as const);
  const I = asEnum(get("I"), ["N", "L", "H"] as const);
  const A = asEnum(get("A"), ["N", "L", "H"] as const);

  if (!AV || !AC || !PR || !UI || !S || !C || !I || !A) {
    return null;
  }

  // If all impact metrics are N (0.0), reject so a real vulnerability isn't scored 0.0
  // due to a malformed model response.
  if (C === "N" && I === "N" && A === "N") {
    return null;
  }

  return calculateCvss({ AV, AC, PR, UI, S, C, I, A });
}

/**
 * Fallback baseline CVSS v3.1 metrics for a qualitative severity bucket when the
 * model did not supply a valid 8-metric vector.
 */
export function fallbackCvssForSeverity(severity: Severity): CvssResult {
  switch (severity) {
    case "critical":
      // 9.8 Critical
      return calculateCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H" });
    case "high":
      // 7.5 High
      return calculateCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "N", A: "N" });
    case "medium":
      // 5.3 Medium
      return calculateCvss({ AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" });
    case "low":
      // 3.7 Low
      return calculateCvss({ AV: "N", AC: "H", PR: "N", UI: "N", S: "U", C: "L", I: "N", A: "N" });
  }
}
