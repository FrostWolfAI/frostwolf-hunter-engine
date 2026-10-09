/**
 * Dev control-plane — a local stand-in for the Cloudflare worker, for E2E testing.
 *
 * In production the worker is Guard + the gateway: it authenticates callers, lends
 * Hunter the D1 binding over `/internal/d1`, and forwards `/v1/hunter/*` to the
 * engine with the confirmed tenant. None of that needs Cloudflare to *test* — this
 * file reproduces the two surfaces the engine actually depends on, backed by a local
 * SQLite file, so `docker compose up` gives a full, offline end-to-end stack:
 *
 *   - POST /internal/d1   run the engine's SQL batch against SQLite (the D1 loan).
 *   - /v1/hunter/*        inject a dev tenant + the shared secret and proxy to the
 *                         engine (the gateway). Streams, so the live-log SSE works.
 *
 * It is intentionally NOT the real worker: no Google OAuth, no sessions, one fixed
 * dev tenant. It exists only so the engine and its pipeline can be exercised locally.
 */

import { DatabaseSync } from "node:sqlite";
import { createServer } from "node:http";
import { readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const PORT = Number(process.env.PORT ?? 8787);
const SECRET = process.env.HUNTER_SECRET ?? "dev-secret";
const HUNTER_URL = (process.env.HUNTER_URL ?? "http://hunter:8080").replace(/\/$/, "");
const DB_PATH = process.env.DB_PATH ?? "/data/hunter.db";
const TENANT = process.env.DEV_TENANT ?? "dev-tenant";
const MIGRATIONS = process.env.MIGRATIONS_DIR ?? join(dirname(fileURLToPath(import.meta.url)), "..", "migrations");

const db = new DatabaseSync(DB_PATH);
applyMigrations();

function applyMigrations() {
  const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql")).sort();
  for (const file of files) {
    const sql = readFileSync(join(MIGRATIONS, file), "utf8");
    for (const stmt of sql.split(/;\s*$/m).map((s) => s.trim()).filter(Boolean)) {
      try {
        db.exec(stmt);
      } catch (error) {
        // ALTER ADD COLUMN isn't idempotent; ignore "duplicate column" on re-runs.
        if (!/duplicate column|already exists/i.test(String(error))) {
          console.error(`migration ${file}: ${error}`);
        }
      }
    }
  }
  console.log(`[dev-worker] migrations applied from ${MIGRATIONS}`);
}

function runStatements(statements) {
  const results = [];
  db.exec("BEGIN");
  try {
    for (const { sql, params = [] } of statements) {
      const prepared = db.prepare(sql);
      const returnsRows = /^\s*(select|with)\b/i.test(sql) || /\breturning\b/i.test(sql);
      if (returnsRows) {
        results.push({ rows: prepared.all(...params), changes: 0 });
      } else {
        const info = prepared.run(...params);
        results.push({ rows: [], changes: Number(info.changes) });
      }
    }
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  return results;
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

function bearer(req) {
  const m = /^bearer\s+(.+)$/i.exec(req.headers.authorization ?? "");
  return m ? m[1].trim() : null;
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://local");

  if (req.method === "GET" && url.pathname === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  // The D1 loan: only the engine (shared secret) may run SQL.
  if (url.pathname === "/internal/d1") {
    if (bearer(req) !== SECRET) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "bad secret" } }));
      return;
    }
    try {
      const body = JSON.parse((await readBody(req)).toString("utf8") || "{}");
      const results = runStatements(body.statements ?? []);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ results }));
    } catch (error) {
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: String(error) } }));
    }
    return;
  }

  // The gateway: a real deployment authenticates the caller here. Locally we inject
  // a fixed dev tenant/role and forward to the engine with the shared secret.
  if (url.pathname.startsWith("/v1/hunter/")) {
    const headers = {
      authorization: `Bearer ${SECRET}`,
      "x-fw-tenant": TENANT,
      "x-fw-role": "owner",
    };
    const ct = req.headers["content-type"];
    if (ct) headers["content-type"] = ct;
    const method = req.method ?? "GET";
    const hasBody = method !== "GET" && method !== "HEAD";
    let upstream;
    try {
      upstream = await fetch(`${HUNTER_URL}${url.pathname}${url.search}`, {
        method,
        headers,
        body: hasBody ? await readBody(req) : undefined,
      });
    } catch (error) {
      res.writeHead(502, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: `engine unreachable: ${error}` } }));
      return;
    }
    const out = {};
    for (const h of ["content-type", "cache-control"]) {
      const v = upstream.headers.get(h);
      if (v) out[h] = v;
    }
    res.writeHead(upstream.status, out);
    if (upstream.body) {
      const reader = upstream.body.getReader();
      res.on("close", () => reader.cancel().catch(() => {}));
      for (;;) {
        const { done, value } = await reader.read();
        if (done || res.destroyed) break;
        res.write(value);
      }
    }
    res.end();
    return;
  }

  res.writeHead(404, { "content-type": "application/json" });
  res.end(JSON.stringify({ error: { message: "not found" } }));
});

server.listen(PORT, () => console.log(`[dev-worker] listening on :${PORT} (tenant=${TENANT}, engine=${HUNTER_URL})`));
