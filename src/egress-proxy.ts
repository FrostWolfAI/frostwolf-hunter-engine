/**
 * Scoped egress proxy — the OS-level network boundary.
 *
 * Runs in the parent process, listens on a loopback port, and enforces the
 * declared scope on all outbound HTTP/HTTPS traffic. The sandboxed child is
 * configured to route all network traffic through this proxy, so even raw
 * socket usage is constrained (the child has no direct network access).
 *
 * This replaces the application-level `scopedFetch` wrapper with a true
 * network boundary that catches all egress, not just `fetch()` calls.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createConnection, type Socket } from "node:net";
import { parse } from "node:url";
import { isInScope } from "./scope.js";

export interface EgressProxyOptions {
  /** The allowlist of hosts this run may reach. */
  readonly hosts: readonly string[];
  /** The port to listen on (0 = auto-assign). */
  readonly port?: number;
  /** Optional callback for logging each request. */
  readonly onRequest?: (url: string, allowed: boolean) => void;
}

export interface EgressProxy {
  /** The URL the child should configure as its HTTP/HTTPS proxy. */
  readonly url: string;
  /** The actual port the proxy is listening on. */
  readonly port: number;
  /** Stop the proxy and free its port. */
  close(): Promise<void>;
}

/**
 * Start a scoped egress proxy.
 *
 * The proxy enforces the allowlist on all HTTP and HTTPS (CONNECT) requests.
 * Requests to hosts not in the allowlist are rejected with a 403.
 */
export async function startEgressProxy(options: EgressProxyOptions): Promise<EgressProxy> {
  const { hosts, port = 0, onRequest } = options;

  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => handleHttp(req, res, hosts, onRequest));

    server.on("error", reject);
    server.listen(port, "127.0.0.1", () => {
      const address = server.address();
      if (address === null || typeof address === "string") {
        reject(new Error("proxy failed to bind"));
        return;
      }
      resolve({
        url: `http://127.0.0.1:${address.port}`,
        port: address.port,
        close: () => new Promise((res) => server.close(() => res())),
      });
    });
  });
}

/** Handle a plain HTTP request. */
function handleHttp(
  req: IncomingMessage,
  res: ServerResponse,
  hosts: readonly string[],
  onRequest?: (url: string, allowed: boolean) => void,
): void {
  if (req.url === undefined) {
    res.writeHead(400);
    res.end("missing URL");
    return;
  }

  const targetUrl = req.url;
  const allowed = isInScope(targetUrl, hosts);
  onRequest?.(targetUrl, allowed);

  if (!allowed) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end(`egress blocked: ${targetUrl} is outside the declared scope`);
    return;
  }

  // Forward the request to the target
  const parsed = parse(targetUrl);
  if (parsed.hostname === undefined) {
    res.writeHead(400);
    res.end("invalid target host");
    return;
  }

  const options = {
    hostname: parsed.hostname,
    port: parsed.port ?? 80,
    path: parsed.path ?? "/",
    method: req.method,
    headers: req.headers,
  };

  const proxyReq = createConnection(options, () => {
    proxyReq.write(
      `${req.method ?? "GET"} ${parsed.path ?? "/"} HTTP/1.1\r\n` +
        Object.entries(req.headers ?? {})
          .map(([k, v]) => `${k}: ${v}\r\n`)
          .join("") +
        "\r\n",
    );
  });

  proxyReq.on("data", (chunk) => res.write(chunk));
  proxyReq.on("end", () => res.end());
  proxyReq.on("error", (err) => {
    res.writeHead(502, { "Content-Type": "text/plain" });
    res.end(`proxy error: ${err.message}`);
  });

  req.pipe(proxyReq);
}

/** Handle an HTTPS CONNECT request (tunneling). */
function handleConnect(
  req: IncomingMessage,
  socket: Socket,
  hosts: readonly string[],
  onRequest?: (url: string, allowed: boolean) => void,
): void {
  if (req.url === undefined) {
    socket.destroy();
    return;
  }

  const [host, portStr] = req.url.split(":");
  const port = portStr !== undefined ? Number.parseInt(portStr, 10) : 443;
  const targetUrl = `https://${host}:${port}`;
  const allowed = isInScope(targetUrl, hosts);
  onRequest?.(targetUrl, allowed);

  if (!allowed) {
    socket.write("HTTP/1.1 403 Forbidden\r\n\r\n");
    socket.destroy();
    return;
  }

  // Tunnel to the target
  const target = createConnection({ host, port }, () => {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    target.pipe(socket);
    socket.pipe(target);
  });

  target.on("error", () => {
    socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
    socket.destroy();
  });

  socket.on("error", () => target.destroy());
}