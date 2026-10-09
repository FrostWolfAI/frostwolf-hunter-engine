/**
 * Hunter's HTTP API.
 *
 * Only the gateway worker calls this. It has already authenticated the caller, so
 * a request here carries the confirmed tenant in `x-fw-tenant` and proves it came
 * from the worker with the shared secret as the bearer. Hunter never sees a cookie
 * or a customer key, and every query below is scoped to that tenant in SQL.
 */

import {
  createConnection,
  createHunt,
  getFinding,
  getHunt,
  getRun,
  listConnections,
  listEvents,
  listFindings,
  listHunts,
  listRuns,
  revokeConnection,
  setFindingStatus,
  startRun,
  stopHunt,
  updateRunStatus,
  type Env,
} from "./data/db.js";
import type { FindingStatus, HuntMode } from "./data/types.js";
import { D1Error } from "./d1.js";
import { errorResponse, jsonResponse, readJson, type Handler } from "./http.js";

const PREFIX = "/v1/hunter/";

const TRIAGE: readonly FindingStatus[] = ["open", "confirmed", "dismissed", "fixed"];
const TERMINAL: readonly string[] = ["completed", "failed", "stopped"];

export interface RouteDeps {
  readonly secret: string;
  readonly env: Env;
  readonly enqueue: (runId: string) => Promise<void>;
  /** A server-sent-event stream of a run's live log. */
  readonly liveStream: (runId: string) => ReadableStream<Uint8Array>;
}

export function createHandler(deps: RouteDeps): Handler {
  return async (request) => {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return jsonResponse({ status: "ok" });
    }

    if (!isFromWorker(request, deps.secret)) {
      return errorResponse(401, "unauthorized", "Not from the gateway.");
    }

    const tenantId = request.headers.get("x-fw-tenant");
    if (tenantId === null || tenantId.length === 0 || !url.pathname.startsWith(PREFIX)) {
      return errorResponse(404, "not_found", `No route for ${url.pathname}.`);
    }

    const segments = url.pathname.slice(PREFIX.length).split("/").filter(Boolean);

    try {
      return await route(request, deps, tenantId, segments);
    } catch (error) {
      if (error instanceof D1Error) {
        return errorResponse(503, "unavailable", "The database is unavailable.");
      }
      throw error;
    }
  };
}

async function route(
  request: Request,
  deps: RouteDeps,
  tenantId: string,
  segments: readonly string[],
): Promise<Response> {
  const { env } = deps;
  const [resource, id, action] = segments;
  const method = request.method;

  switch (resource) {
    case "connections": {
      if (id === undefined && method === "GET") {
        return jsonResponse({ connections: await listConnections(env, tenantId) });
      }
      if (id === undefined && method === "POST") {
        const body = await readJson(request);
        const provider = body === null ? null : asString(body.provider);
        if (body === null || provider === null) {
          return errorResponse(400, "bad_request", "`provider` is required.");
        }
        const connection = await createConnection(env, tenantId, {
          provider,
          repos: asStringArray(body.repos),
          runtime: asObject(body.runtime),
        });
        return jsonResponse({ connection }, 201);
      }
      if (id !== undefined && action === undefined && method === "DELETE") {
        return (await revokeConnection(env, tenantId, id))
          ? jsonResponse({ revoked: true })
          : errorResponse(404, "not_found", "No such connection.");
      }
      break;
    }

    case "hunts": {
      if (id === undefined && method === "GET") {
        return jsonResponse({ hunts: await listHunts(env, tenantId) });
      }
      if (id === undefined && method === "POST") {
        const body = await readJson(request);
        const connectionId = body === null ? null : asString(body.connection_id);
        if (body === null || connectionId === null) {
          return errorResponse(400, "bad_request", "`connection_id` is required.");
        }
        const hunt = await createHunt(env, tenantId, {
          connection_id: connectionId,
          mode: (body.mode === "continuous" ? "continuous" : "oneshot") satisfies HuntMode,
          scope: asObject(body.scope),
          depth: asString(body.depth) ?? "standard",
          policy: asObject(body.policy),
        });
        return hunt === null
          ? errorResponse(404, "not_found", "No such connection.")
          : jsonResponse({ hunt }, 201);
      }
      if (id === undefined) {
        break;
      }
      if (action === undefined && method === "GET") {
        const hunt = await getHunt(env, tenantId, id);
        return hunt === null
          ? errorResponse(404, "not_found", "No such hunt.")
          : jsonResponse({ hunt });
      }
      if (action === "runs" && method === "GET") {
        return (await getHunt(env, tenantId, id)) === null
          ? errorResponse(404, "not_found", "No such hunt.")
          : jsonResponse({ runs: await listRuns(env, tenantId, id) });
      }
      if (action === "start" && method === "POST") {
        const run = await startRun(env, tenantId, id);
        if (run === null) {
          return errorResponse(404, "not_found", "No such hunt.");
        }
        try {
          await deps.enqueue(run.id);
        } catch {
          // Redis is down: the run exists but will never be picked up, so say so
          // rather than leave it `queued` forever.
          await updateRunStatus(env, run.id, { status: "failed", stage: "queue" });
          return errorResponse(503, "unavailable", "The queue is unavailable.");
        }
        return jsonResponse({ run }, 202);
      }
      if (action === "stop" && method === "POST") {
        return (await stopHunt(env, tenantId, id))
          ? jsonResponse({ stopped: true })
          : errorResponse(404, "not_found", "No such hunt.");
      }
      break;
    }

    case "findings": {
      if (id === undefined && method === "GET") {
        return jsonResponse({ findings: await listFindings(env, tenantId) });
      }
      if (id !== undefined && action === undefined && method === "GET") {
        const finding = await getFinding(env, tenantId, id);
        return finding === null
          ? errorResponse(404, "not_found", "No such finding.")
          : jsonResponse({ finding });
      }
      if (id !== undefined && action === undefined && method === "PATCH") {
        const body = await readJson(request);
        const status = TRIAGE.find((candidate) => candidate === body?.status);
        if (status === undefined) {
          return errorResponse(400, "bad_request", `\`status\` must be one of ${TRIAGE.join(", ")}.`);
        }
        if (!(await setFindingStatus(env, tenantId, id, status))) {
          return errorResponse(404, "not_found", "No such finding.");
        }
        return jsonResponse({ finding: await getFinding(env, tenantId, id) });
      }
      break;
    }

    case "runs": {
      if (id !== undefined && action === "stream" && method === "GET") {
        return streamRun(deps, tenantId, id);
      }
      if (id !== undefined && action === "events" && method === "GET") {
        return eventsForRun(deps, tenantId, id, request);
      }
      break;
    }

    case "analytics": {
      if (id === undefined && method === "GET") {
        const findings = await listFindings(env, tenantId);
        const bySeverity: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
        for (const finding of findings) {
          bySeverity[finding.severity] = (bySeverity[finding.severity] ?? 0) + 1;
        }
        return jsonResponse({
          findings_total: findings.length,
          by_severity: bySeverity,
          open: findings.filter((f) => f.status === "open").length,
          confirmed: findings.filter((f) => f.status === "confirmed").length,
        });
      }
      break;
    }
  }

  return errorResponse(404, "not_found", `No route for ${request.method} ${new URL(request.url).pathname}.`);
}

/**
 * Stream a run's log.
 *
 * The run is looked up under the tenant first, so a caller can only ever watch
 * their own. A run that is still going streams live from Redis; one that has
 * finished is replayed from the durable copy in D1.
 */
async function streamRun(deps: RouteDeps, tenantId: string, runId: string): Promise<Response> {
  const run = await getRun(deps.env, tenantId, runId);
  if (run === null) {
    return errorResponse(404, "not_found", "No such run.");
  }

  const headers = {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-store",
  };

  if (!TERMINAL.includes(run.status)) {
    return new Response(deps.liveStream(runId), { status: 200, headers });
  }

  const events = await listEvents(deps.env, tenantId, runId, 0);
  const body = events
    .map((e) => `data: ${JSON.stringify({ level: e.level, stage: e.stage, message: e.message, ts: e.ts })}\n\n`)
    .join("");
  return new Response(body, { status: 200, headers });
}

/**
 * A run's log as a plain page of JSON, for a caller that is not an `EventSource` —
 * the console reopening a finished run, a CLI, anything that wants to page through
 * rather than hold a connection open. Live or finished, it reads the same durable
 * copy in D1 that `streamRun` replays from once a run is terminal, so a line is
 * visible here the moment it is visible there.
 */
async function eventsForRun(
  deps: RouteDeps,
  tenantId: string,
  runId: string,
  request: Request,
): Promise<Response> {
  const run = await getRun(deps.env, tenantId, runId);
  if (run === null) {
    return errorResponse(404, "not_found", "No such run.");
  }

  const after = Number.parseInt(new URL(request.url).searchParams.get("after") ?? "0", 10);
  const events = await listEvents(deps.env, tenantId, runId, Number.isFinite(after) ? after : 0);
  return jsonResponse({ run, events });
}

/** Whether the request carries the shared secret. */
function isFromWorker(request: Request, secret: string): boolean {
  if (secret.length === 0) {
    return false;
  }
  const match = /^bearer\s+(.+)$/i.exec(request.headers.get("authorization")?.trim() ?? "");
  return match !== null && timingSafeEqual(match[1]!.trim(), secret);
}

function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for (let index = 0; index < a.length; index++) {
    diff |= a.charCodeAt(index) ^ b.charCodeAt(index);
  }
  return diff === 0;
}

function asString(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function asStringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}
