/**
 * A small bridge from Node's HTTP server to the fetch API.
 *
 * Routes are written as `(Request) => Response`, which keeps them readable and
 * lets a test call them directly. A streamed body, such as the live log, is piped
 * through as it is produced, and a watcher who disconnects cancels it.
 */

import { createServer, type IncomingMessage, type Server } from "node:http";
import { Readable } from "node:stream";

export type Handler = (request: Request) => Promise<Response>;

/** Largest JSON body a route will read, in characters. */
const MAX_BODY_CHARS = 1_000_000;

export function serve(handler: Handler): Server {
  return createServer((req, res) => {
    void (async () => {
      let response: Response;
      try {
        response = await handler(toRequest(req));
      } catch {
        response = jsonResponse({ error: { type: "internal_error", code: "internal_error", message: "Internal error." } }, 500);
      }

      res.writeHead(response.status, Object.fromEntries(response.headers));
      if (response.body === null) {
        res.end();
        return;
      }

      const reader = response.body.getReader();
      res.on("close", () => void reader.cancel().catch(() => undefined));
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done || res.destroyed) {
            break;
          }
          res.write(value);
        }
      } catch {
        // The stream was cancelled or failed; nothing more to send.
      }
      res.end();
    })();
  });
}

function toRequest(req: IncomingMessage): Request {
  const headers = new Headers();
  for (const [name, value] of Object.entries(req.headers)) {
    if (typeof value === "string") {
      headers.set(name, value);
    }
  }

  const hasBody = req.method !== "GET" && req.method !== "HEAD";
  return new Request(`http://${req.headers.host ?? "hunter"}${req.url ?? "/"}`, {
    method: req.method ?? "GET",
    headers,
    ...(hasBody
      ? { body: Readable.toWeb(req) as ReadableStream, duplex: "half" }
      : {}),
  } as RequestInit);
}

export function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
}

/** The error envelope the console already understands. */
export function errorResponse(status: number, code: string, message: string): Response {
  return jsonResponse({ error: { type: code, code, message } }, status);
}

/** Read a JSON object body, or null when it is missing, too large, or not an object. */
export async function readJson(request: Request): Promise<Record<string, unknown> | null> {
  try {
    const text = await request.text();
    if (text.length > MAX_BODY_CHARS) {
      return null;
    }
    const parsed = JSON.parse(text) as unknown;
    return parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}
