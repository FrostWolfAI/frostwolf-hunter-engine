/**
 * What the runner needs from the database, as one small interface.
 *
 * The runner depends on this rather than on D1 directly, so it can be tested with
 * an in-memory fake and so the data layer stays the only place that writes SQL.
 */

import {
  appendEvents,
  getRunJob,
  incrementUsage,
  insertFinding,
  insertHypothesis,
  insertVerdict,
  isRunStopped,
  resolveHypothesisId,
  setHypothesisStatus,
  updateRunStatus,
  type Env,
} from "./data/db.js";
import type { HypothesisStatus } from "./data/types.js";
import type { Finding, Hypothesis, JevVerdict, RunEvent, RunJob, RunStatus } from "./types.js";

export interface Store {
  getJob(runId: string): Promise<RunJob | null>;
  isStopped(runId: string): Promise<boolean>;
  setStatus(
    runId: string,
    status: RunStatus,
    extra?: { stage?: string; cost_usd?: number },
  ): Promise<void>;
  appendEvents(runId: string, events: readonly RunEvent[]): Promise<void>;
  addHypothesis(runId: string, hypothesis: Hypothesis): Promise<void>;
  setHypothesisStatus(runId: string, code: string, status: HypothesisStatus): Promise<void>;
  addVerdict(runId: string, gate: string, hypothesisCode: string | undefined, verdict: JevVerdict): Promise<void>;
  addFinding(runId: string, finding: Finding): Promise<void>;
  meter(runId: string, usage: { hunts?: number; verifications?: number }): Promise<void>;
}

export function createStore(env: Env): Store {
  return {
    getJob: (runId) => getRunJob(env, runId),
    isStopped: (runId) => isRunStopped(env, runId),
    async setStatus(runId, status, extra = {}) {
      await updateRunStatus(env, runId, {
        status,
        stage: extra.stage,
        cost_usd: extra.cost_usd,
      });
    },
    async appendEvents(runId, events) {
      await appendEvents(env, runId, events);
    },
    async addHypothesis(runId, hypothesis) {
      await insertHypothesis(env, runId, hypothesis);
    },
    async setHypothesisStatus(runId, code, status) {
      await setHypothesisStatus(env, runId, code, status);
    },
    async addVerdict(runId, gate, hypothesisCode, verdict) {
      await insertVerdict(env, {
        run_id: runId,
        hypothesis_code: hypothesisCode,
        gate,
        verdict: verdict.verdict,
        confidence: verdict.confidence,
        evidence_refs: verdict.evidence_refs,
        rationale: verdict.rationale,
        next: verdict.next,
      });
    },
    async addFinding(runId, finding) {
      const hypothesisId =
        finding.hypothesis_code === undefined
          ? undefined
          : ((await resolveHypothesisId(env, runId, finding.hypothesis_code)) ?? undefined);
      await insertFinding(env, {
        run_id: runId,
        hypothesis_id: hypothesisId,
        title: finding.title,
        severity: finding.severity,
        novelty_class: finding.novelty_class,
        cwe: finding.cwe,
        owasp: finding.owasp,
        repro_ratio: finding.repro_ratio,
        mechanism: finding.mechanism,
        location: finding.location,
        remediation: finding.remediation,
        evidence: finding.evidence,
      });
    },
    async meter(runId, usage) {
      await incrementUsage(env, runId, usage);
    },
  };
}
