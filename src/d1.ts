/**
 * D1, reached through the gateway worker.
 *
 * D1 is only reachable from a Worker binding, so Hunter lends the Worker's generic
 * `/internal/d1` endpoint, authenticated with the one shared secret. This mirrors
 * the small slice of the D1 binding API the data layer uses (`prepare`, `bind`,
 * `first`, `all`, `run`, `batch`), so the queries read exactly as they would
 * inside the worker.
 */

import type { Config } from "./config.js";

type Param = string | number | boolean | null;

interface Row {
  readonly rows: unknown[];
  readonly changes: number;
}

/** A failed or unreachable database. The caller decides whether that is fatal. */
export class D1Error extends Error {
  constructor(message: string) {
    super(message);
    this.name = "D1Error";
  }
}

/** One statement, ready to bind and run. */
export class Statement {
  constructor(
    private readonly client: D1Client,
    readonly sql: string,
    readonly params: readonly Param[] = [],
  ) {}

  bind(...params: Param[]): Statement {
    return new Statement(this.client, this.sql, params);
  }

  async first<T>(): Promise<T | null> {
    const [result] = await this.client.execute([this]);
    return (result?.rows[0] as T | undefined) ?? null;
  }

  async all<T>(): Promise<{ results: T[] }> {
    const [result] = await this.client.execute([this]);
    return { results: (result?.rows ?? []) as T[] };
  }

  async run(): Promise<{ meta: { changes: number } }> {
    const [result] = await this.client.execute([this]);
    return { meta: { changes: result?.changes ?? 0 } };
  }
}

/** The database handle the data layer is written against. */
export interface Db {
  prepare(sql: string): Statement;
  batch(statements: readonly Statement[]): Promise<Array<{ meta: { changes: number } }>>;
}

export class D1Client implements Db {
  private readonly url: string;
  private readonly secret: string;

  constructor(config: Pick<Config, "workerUrl" | "secret">) {
    this.url = `${config.workerUrl}/internal/d1`;
    this.secret = config.secret;
  }

  prepare(sql: string): Statement {
    return new Statement(this, sql);
  }

  async batch(
    statements: readonly Statement[],
  ): Promise<Array<{ meta: { changes: number } }>> {
    const results = await this.execute(statements);
    return results.map((result) => ({ meta: { changes: result.changes } }));
  }

  /** Run statements as one atomic request. */
  async execute(statements: readonly Statement[]): Promise<Row[]> {
    let response: Response;
    try {
      response = await fetch(this.url, {
        method: "POST",
        headers: {
          authorization: `Bearer ${this.secret}`,
          "content-type": "application/json",
        },
        body: JSON.stringify({
          statements: statements.map((s) => ({ sql: s.sql, params: s.params })),
        }),
      });
    } catch {
      throw new D1Error("The database did not answer.");
    }

    if (!response.ok) {
      const body = (await response.json().catch(() => null)) as {
        error?: { message?: string };
      } | null;
      throw new D1Error(body?.error?.message ?? `Database error ${response.status}.`);
    }

    const body = (await response.json()) as { results: Row[] };
    return body.results;
  }
}
