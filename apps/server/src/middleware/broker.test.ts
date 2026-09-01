import { createServer, type Server } from "node:http";
import { afterEach, describe, expect, it } from "vitest";
import { ArkBroker } from "./broker.js";

const REAL_KEY = "ark-real-key-that-must-never-leave-the-control-plane";

interface Upstream {
  server: Server;
  port: number;
  seen: Array<{ auth: string; path: string; body: string }>;
}

async function startUpstream(): Promise<Upstream> {
  const seen: Upstream["seen"] = [];
  const server = createServer((request, response) => {
    let body = "";
    request.on("data", (chunk) => (body += chunk));
    request.on("end", () => {
      seen.push({
        auth: request.headers.authorization ?? "",
        path: request.url ?? "",
        body,
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  const port = typeof address === "object" && address ? address.port : 0;
  return { server, port, seen };
}

const open: Array<() => Promise<void>> = [];

afterEach(async () => {
  await Promise.all(open.splice(0).map((close) => close()));
});

async function harness() {
  const upstream = await startUpstream();
  open.push(
    () => new Promise<void>((resolve) => upstream.server.close(() => resolve())),
  );
  const broker = new ArkBroker({
    arkBaseUrl: "http://127.0.0.1:" + upstream.port + "/api/v3",
    arkApiKey: REAL_KEY,
    host: "127.0.0.1",
    port: 0,
    maxCallsPerRun: 3,
  });
  await broker.start();
  open.push(() => broker.stop());
  return { upstream, broker };
}

describe("Ark credential broker", () => {
  it("swaps a run token for the real key without the Runtime ever seeing it", async () => {
    const { upstream, broker } = await harness();
    const token = broker.issue("agent-1", "run-1");
    expect(token).not.toContain(REAL_KEY);

    const response = await fetch(broker.baseUrlFor("127.0.0.1") + "/responses", {
      method: "POST",
      headers: { authorization: "Bearer " + token, "content-type": "application/json" },
      body: JSON.stringify({ input: "hi" }),
    });

    expect(response.status).toBe(200);
    expect(upstream.seen).toHaveLength(1);
    expect(upstream.seen[0]?.auth).toBe("Bearer " + REAL_KEY);
    expect(upstream.seen[0]?.path).toBe("/api/v3/responses");
  });

  // A credential read out of the Runtime is worthless the moment the turn ends.
  it("refuses a token after its run is revoked", async () => {
    const { upstream, broker } = await harness();
    const token = broker.issue("agent-1", "run-1");
    broker.revokeRun("run-1");

    const response = await fetch(broker.baseUrlFor("127.0.0.1") + "/responses", {
      method: "POST",
      headers: { authorization: "Bearer " + token },
    });

    expect(response.status).toBe(401);
    expect(upstream.seen).toHaveLength(0);
  });

  it("refuses a forged token", async () => {
    const { upstream, broker } = await harness();
    const response = await fetch(broker.baseUrlFor("127.0.0.1") + "/responses", {
      method: "POST",
      headers: { authorization: "Bearer ark-run-not-a-real-lease" },
    });
    expect(response.status).toBe(401);
    expect(upstream.seen).toHaveLength(0);
  });

  it("caps the model calls one run may make", async () => {
    const { broker } = await harness();
    const token = broker.issue("agent-1", "run-1");
    const call = () =>
      fetch(broker.baseUrlFor("127.0.0.1") + "/responses", {
        method: "POST",
        headers: { authorization: "Bearer " + token },
      });
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(200);
    expect((await call()).status).toBe(429);
  });

  it("reports every forwarded call for the trace", async () => {
    const records: string[] = [];
    const upstream = await startUpstream();
    open.push(() => new Promise<void>((resolve) => upstream.server.close(() => resolve())));
    const broker = new ArkBroker({
      arkBaseUrl: "http://127.0.0.1:" + upstream.port + "/api/v3",
      arkApiKey: REAL_KEY,
      host: "127.0.0.1",
      port: 0,
      maxCallsPerRun: 10,
      onCall: (record) => records.push(record.runId + ":" + record.status),
    });
    await broker.start();
    open.push(() => broker.stop());

    const token = broker.issue("agent-1", "run-7");
    await fetch(broker.baseUrlFor("127.0.0.1") + "/responses", {
      method: "POST",
      headers: { authorization: "Bearer " + token },
    });
    expect(records).toEqual(["run-7:200"]);
  });
});
