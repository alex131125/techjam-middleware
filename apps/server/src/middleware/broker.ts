/**
 * L2 - Ark credential broker.
 *
 * The Runtime never receives the real Ark API key. Instead the control plane mints a
 * single-use, run-scoped token, injects THAT into the Runtime, and points the Codex
 * `base_url` at this broker. The broker authenticates the run token, swaps in the real
 * key, and forwards to Ark.
 *
 * Consequences that matter for the threat model:
 *  - `printenv ARK_API_KEY` inside the Runtime yields a token that is worthless once the
 *    run ends, and that can only ever reach Ark through this process.
 *  - Every model call becomes an observable event, which is where the trace's
 *    `model.call` spans come from.
 *  - Combined with the internal container network (no route off-host), the broker is the
 *    ONLY reachable network endpoint for the Runtime.
 */

import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { request as httpsRequest } from "node:https";
import { randomBytes } from "node:crypto";

export interface BrokerLease {
  token: string;
  agentId: string;
  runId: string;
  issuedAt: number;
  calls: number;
}

export interface BrokerCallRecord {
  agentId: string;
  runId: string;
  status: number;
  path: string;
  durationMs: number;
}

export interface ArkBrokerOptions {
  arkBaseUrl: string;
  arkApiKey: string;
  host: string;
  port: number;
  maxCallsPerRun: number;
  onCall?: (record: BrokerCallRecord) => void;
  onDenied?: (reason: string, path: string) => void;
}

const PREFIX = "/ark";

export class ArkBroker {
  private server: Server | null = null;
  private readonly leases = new Map<string, BrokerLease>();
  private boundPort = 0;

  constructor(private readonly options: ArkBrokerOptions) {}

  /** Mint a run-scoped credential. Revoked the moment the run finishes. */
  issue(agentId: string, runId: string): string {
    const token = "ark-run-" + randomBytes(24).toString("base64url");
    this.leases.set(token, { token, agentId, runId, issuedAt: Date.now(), calls: 0 });
    return token;
  }

  revoke(token: string | null | undefined): void {
    if (token) this.leases.delete(token);
  }

  revokeRun(runId: string): void {
    for (const [token, lease] of this.leases) {
      if (lease.runId === runId) this.leases.delete(token);
    }
  }

  activeLeaseCount(): number {
    return this.leases.size;
  }

  get port(): number {
    return this.boundPort;
  }

  /** Base URL to write into the Runtime's codex config.toml. */
  baseUrlFor(hostname: string): string {
    return "http://" + hostname + ":" + this.boundPort + PREFIX;
  }

  async start(): Promise<void> {
    if (this.server) return;
    const server = createServer((request, response) => {
      void this.handle(request, response);
    });
    server.headersTimeout = 0;
    server.requestTimeout = 0;
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(this.options.port, this.options.host, () => {
        server.removeListener("error", reject);
        resolve();
      });
    });
    const address = server.address();
    this.boundPort = typeof address === "object" && address ? address.port : this.options.port;
    this.server = server;
  }

  async stop(): Promise<void> {
    const server = this.server;
    if (!server) return;
    this.server = null;
    this.leases.clear();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  private deny(response: ServerResponse, status: number, reason: string, path: string): void {
    this.options.onDenied?.(reason, path);
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: { message: reason, type: "broker_denied" } }));
  }

  private async handle(request: IncomingMessage, response: ServerResponse): Promise<void> {
    const url = request.url ?? "/";
    if (url === "/healthz") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true, leases: this.leases.size }));
      return;
    }
    if (!url.startsWith(PREFIX)) {
      this.deny(response, 404, "Unknown broker path", url);
      return;
    }

    const header = request.headers.authorization ?? "";
    const token = header.replace(/^Bearer\s+/i, "").trim();
    const lease = this.leases.get(token);
    if (!lease) {
      // An expired or forged token is the expected signature of a leaked credential
      // being replayed after its run ended.
      this.deny(response, 401, "Run credential is not valid or has been revoked", url);
      return;
    }
    if (lease.calls >= this.options.maxCallsPerRun) {
      this.deny(response, 429, "Run exceeded its model-call budget", url);
      return;
    }
    lease.calls += 1;

    const upstreamPath = url.slice(PREFIX.length) || "/";
    const target = new URL(this.options.arkBaseUrl.replace(/\/+$/, "") + upstreamPath);
    const transport = target.protocol === "https:" ? httpsRequest : httpRequest;

    const headers: Record<string, string> = {};
    for (const [name, value] of Object.entries(request.headers)) {
      if (typeof value !== "string") continue;
      const lower = name.toLowerCase();
      if (lower === "host" || lower === "authorization" || lower === "content-length") continue;
      headers[name] = value;
    }
    headers.authorization = "Bearer " + this.options.arkApiKey;
    headers.host = target.host;

    const startedAt = Date.now();
    const upstream = transport(
      {
        protocol: target.protocol,
        hostname: target.hostname,
        port: target.port || (target.protocol === "https:" ? 443 : 80),
        path: target.pathname + target.search,
        method: request.method,
        headers,
      },
      (upstreamResponse) => {
        this.options.onCall?.({
          agentId: lease.agentId,
          runId: lease.runId,
          status: upstreamResponse.statusCode ?? 0,
          path: upstreamPath,
          durationMs: Date.now() - startedAt,
        });
        response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
        upstreamResponse.pipe(response);
      },
    );

    upstream.on("error", (error) => {
      if (!response.headersSent) {
        response.writeHead(502, { "content-type": "application/json" });
      }
      response.end(
        JSON.stringify({ error: { message: "Broker upstream error: " + error.message } }),
      );
    });

    request.pipe(upstream);
  }
}
