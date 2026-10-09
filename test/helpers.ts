import { mkdtempSync, readFileSync, rmSync, writeFileSync, mkdirSync } from "node:fs";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Db } from "../src/d1.js";
import { Statement } from "../src/d1.js";
import type { Env } from "../src/data/db.js";
import type { PreparedRepo } from "../src/repo.js";

type Sqlite = {
  DatabaseSync: new (path: string) => {
    exec(sql: string): void;
    prepare(sql: string): {
      all(...params: unknown[]): unknown[];
      run(...params: unknown[]): { changes: number | bigint };
    };
  };
};

/**
 * An in-memory SQLite database with the real Hunter schema, behind the same
 * interface as the D1 client. D1 is SQLite, so the SQL under test is the SQL that
 * ships.
 */
export function memoryEnv(): Env {
  const { DatabaseSync } = createRequire(import.meta.url)("node:sqlite") as Sqlite;
  const sqlite = new DatabaseSync(":memory:");
  for (const migration of [
    "0001_hunter.sql",
    "0002_hunter_verdicts.sql",
    "0003_hunter_finding_detail.sql",
  ]) {
    sqlite.exec(readFileSync(new URL(`../migrations/${migration}`, import.meta.url), "utf8"));
  }

  const run = (statement: Statement): { rows: unknown[]; changes: number } => {
    const prepared = sqlite.prepare(statement.sql);
    const returnsRows = /^\s*(select|with)\b/i.test(statement.sql) || /\breturning\b/i.test(statement.sql);
    if (returnsRows) {
      return { rows: prepared.all(...statement.params), changes: 0 };
    }
    return { rows: [], changes: Number(prepared.run(...statement.params).changes) };
  };

  const client = {
    async execute(statements: readonly Statement[]) {
      return statements.map(run);
    },
  };

  const db: Db = {
    prepare: (sql) => new Statement(client as never, sql),
    async batch(statements) {
      return statements.map((statement) => ({ meta: { changes: run(statement).changes } }));
    },
  };
  return { DB: db };
}

/**
 * Create a throwaway on-disk repository with a file the scripted model points at,
 * so the real repo-read and white-box validation run against actual source rather
 * than a mock. Stands in for `cloneRepo` in tests. Each call is independent and is
 * deleted by `cleanup()` (the runner calls it after the run).
 */
export function createFixtureRepo(): PreparedRepo {
  const dir = mkdtempSync(join(tmpdir(), "hunter-fixture-"));
  mkdirSync(join(dir, "src"), { recursive: true });
  writeFileSync(
    join(dir, "src", "auth.js"),
    [
      "export function handler(req, res) {",
      "  // Trusts a client-supplied id with no server-side ownership check.",
      "  const userId = req.query.userId;",
      "  return res.json(db.accountFor(userId));",
      "}",
      "",
    ].join("\n"),
  );
  writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "fixture", version: "1.0.0" }));
  return {
    dir,
    async cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

