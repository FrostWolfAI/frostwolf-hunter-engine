/**
 * Executing one run's stages and reporting to a parent.
 *
 * This is the whole of what runs inside the sandbox. It is separate from the process
 * plumbing so the same code runs in the forked child and, in tests, in-process. The
 * injectables (`makeClient`, `baseFetch`, `broker`) default to the real provider, the
 * real network, and a disabled broker; a test overrides them to drive the real stage
 * logic without a live model, target, container, or search key.
 *
 * `broker` is how the child reaches the privileged tools it cannot run itself — `bash`
 * (in the container) and `web_search` (via the search key). In the forked child it is
 * an IPC call to the parent; nothing here holds a key or spawns a process.
 */

import { runAgent } from "./agent.js";
import { createChatJudge, createGlinerJudge, createPassthroughJudge } from "./judge.js";
import { createModelClient, type ModelConfig } from "./models/index.js";
import type { ModelClient } from "./models/types.js";
import { createOrbcodeExplorer, type ExecFn, type ExploreTask } from "./orbcode.js";
import { RepoTools, buildToolset, type BrokeredTool } from "./tools.js";
import { scopedFetch, scopeHosts } from "./scope.js";
import { runStages, type RunContext } from "./state-machine.js";
import { STAGES } from "./stages/index.js";
import type { ChildMessage, RunInput } from "./types.js";

/** Runs a privileged (bash / web_search) tool on the child's behalf. */
export type ToolBroker = (tool: "bash" | "web_search", args: Record<string, unknown>) => Promise<string>;

const disabledBroker: ToolBroker = async () => "unavailable: this tool is not configured for the run.";

export interface PipelineDeps {
  readonly makeClient?: ((config: ModelConfig) => ModelClient) | undefined;
  readonly baseFetch?: typeof fetch | undefined;
  readonly broker?: ToolBroker | undefined;
  /** Override how orbcode is spawned (tests inject a fake). */
  readonly orbcodeExec?: ExecFn | undefined;
}

export async function executeRun(
  input: RunInput,
  post: (message: ChildMessage) => void,
  deps: PipelineDeps = {},
): Promise<void> {
  const { job, credentials, capabilities, repoDir } = input;
  const makeClient = deps.makeClient ?? createModelClient;
  const broker = deps.broker ?? disabledBroker;

  const failClosed = (message: string, reason: string): void => {
    post({
      type: "event",
      event: { level: "error", stage: "intake", message, ts: new Date().toISOString() },
    });
    post({ type: "done", ok: false, reason });
  };

  if (
    credentials.aiApiKey.length === 0 ||
    credentials.attackerModel.length === 0 ||
    credentials.verifierModel.length === 0
  ) {
    failClosed("AI inference is not configured (missing API key or model name).", "ai_not_configured");
    return;
  }

  // Generator runtime. orbcode is the default and the only wired real runtime; it
  // NEVER silently falls back to the built-in loop. `claude`/`codex` are reserved
  // and fail clearly until wired. `internal` is the built-in loop, for tests only.
  if (credentials.agentRuntime === "claude" || credentials.agentRuntime === "codex") {
    failClosed(
      `generator runtime "${credentials.agentRuntime}" is selected but not wired yet; use AGENT_RUNTIME=orbcode`,
      "generator_runtime_not_wired",
    );
    return;
  }
  if (credentials.agentRuntime === "orbcode" && (repoDir === null || credentials.orbcodeBin.length === 0)) {
    failClosed(
      "orbcode runtime requires a cloned repository and ORBCODE_BIN; refusing to fall back to the built-in loop",
      "orbcode_unavailable",
    );
    return;
  }

  // Local read-only tools over the checkout; a sentinel root when there is no repo
  // (intake refuses such a run before any tool is used).
  const repoTools = new RepoTools(repoDir ?? "/dev/null/no-repo");
  const brokered: { bash?: BrokeredTool; webSearch?: BrokeredTool } = {
    bash: capabilities.bash ? (args) => broker("bash", args) : null,
    webSearch: capabilities.webSearch ? (args) => broker("web_search", args) : null,
  };
  const toolset = buildToolset(repoTools, brokered);

  let usedTokens = 0;
  const budget = {
    add(tokens: number): void {
      usedTokens += tokens;
    },
    exceeded(): boolean {
      return usedTokens >= credentials.maxRunTokens;
    },
  };

  const emit = (level: "debug" | "info" | "warn" | "error", stage: string, message: string): void =>
    post({ type: "event", event: { level, stage, message, ts: new Date().toISOString() } });

  // The generator substrate. orbcode (a real agent harness) when configured and a
  // repo is present; otherwise the built-in agent loop. Read-only here — the
  // `--yolo` execute mode belongs to the container sandbox, not this process.
  const orbcode =
    credentials.agentRuntime === "orbcode" && repoDir !== null && credentials.orbcodeBin.length > 0
      ? createOrbcodeExplorer(
          {
            bin: credentials.orbcodeBin,
            baseUrl: credentials.aiBaseUrl,
            apiKey: credentials.aiApiKey,
            models: [credentials.attackerModel, credentials.verifierModel],
            execute: false,
            timeoutMs: 300_000,
            scratchDir: input.scratchDir,
          },
          repoDir,
          (level, stage, message) => emit(level, stage, message),
          (tokens) => {
            budget.add(tokens);
            post({ type: "spend", usd: (tokens / 1000) * credentials.costPer1kTokensUsd });
          },
          deps.orbcodeExec,
        )
      : null;

  const client = makeClient(credentials);

  // The JEV judge backend. `skip` (the default) calls no model — it clears every
  // gate so the recon → synthesis → validate → verify flow runs end to end while
  // the real judge is reworked; the generators and verify's independent
  // re-derivation still do their own work. `gliner` uses the decision model,
  // `chat` the LLM. A decision model with no dedicated service is reached through
  // the same gateway as the other roles, under the same key.
  const viaGateway = credentials.judgeBaseUrl.length === 0;
  const judge =
    credentials.judgeProvider === "gliner"
      ? createGlinerJudge(
          viaGateway ? credentials.aiBaseUrl : credentials.judgeBaseUrl,
          viaGateway ? { apiKey: credentials.aiApiKey, model: credentials.judgeModel } : {},
        )
      : credentials.judgeProvider === "chat"
        ? createChatJudge(client, credentials.judgeModel)
        : createPassthroughJudge();

  const ctx: RunContext = {
    job,
    repoDir,
    tools: toolset,
    budget,
    judge,
    models: {
      attackerModel: credentials.attackerModel,
      verifierModel: credentials.verifierModel,
      judgeModel: credentials.judgeModel,
      verifyN: credentials.verifyN,
      costPer1kTokensUsd: credentials.costPer1kTokensUsd,
    },
    client,
    fetch: scopedFetch(scopeHosts(job), deps.baseFetch),
    scratch: {},
    explore: <T>(task: ExploreTask): Promise<T | null> =>
      orbcode !== null
        ? orbcode<T>(task)
        : runAgent<T>(ctx, {
            model: task.model,
            system: task.system,
            task: task.task,
            stage: task.stage,
            maxSteps: task.maxSteps ?? 10,
            ...(task.temperature === undefined ? {} : { temperature: task.temperature }),
          }),
    emit,
    hypothesis: (hypothesis) => post({ type: "hypothesis", hypothesis }),
    hypothesisStatus: (code, status) => post({ type: "hypothesis_status", code, status }),
    verdict: (gate, hypothesis_code, verdict) =>
      post({ type: "verdict", gate, hypothesis_code, verdict }),
    promote: (finding) => post({ type: "finding", finding }),
    spend: (usd) => post({ type: "spend", usd }),
  };

  const result = await runStages(ctx, STAGES, (name) => post({ type: "stage", name }));

  post({
    type: "done",
    ok: result.status === "completed",
    ...(result.reason === undefined ? {} : { reason: result.reason }),
  });
}
