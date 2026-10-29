/**
 * Executes every transport-http vector over real HTTP against the in-repo
 * server stub (test/support/sse-stub.ts). go-wmp's secured server is not
 * released yet; this is the executor wmp-js and the stub are both checked by.
 */
import { describe, it, afterEach, expect } from "vitest";
import { SseStub } from "./support/sse-stub.js";
import { runTransportVector } from "./support/transport-vector-runner.js";
import { loadManifest, loadVectors, type TestVector } from "./vectors.js";

const files = loadManifest().filter((e) => e.kind === "transport-http");

describe("transport-http vectors", () => {
  let stub: SseStub | undefined;
  afterEach(async () => {
    await stub?.stop();
    stub = undefined;
  });

  for (const f of files) {
    for (const v of loadVectors<TestVector>(f.file)) {
      it(`${v.id}: ${v.description}`, async () => {
        stub = new SseStub({
          eventBuffer: v.setup?.event_buffer ?? 200,
          principals: v.setup?.principals ?? {},
        });
        await stub.start();
        const s = stub;
        await runTransportVector(v.input, {
          baseUrl: s.url,
          emit: (sid, m) => s.emit(sid, m),
          advance: (sec) => s.advance(sec),
          drop: (sid) => s.dropConnections(sid),
        });
      });
    }
  }
});

describe("the runner refuses what it should", () => {
  it("fails a stream expectation answered by a non-stream 200 response", async () => {
    const { createServer } = await import("node:http");
    const server = createServer((_req, res) => {
      res.writeHead(200, { "Content-Type": "application/json" }).end("{}");
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const steps = [
      {
        step: "open a stream",
        conn: "A",
        request: { method: "GET", path: "/wmp/events", headers: { Accept: "text/event-stream" } },
        expect: { status: 200, events: [] },
      },
    ];
    try {
      await expect(
        runTransportVector(steps, { baseUrl: `http://127.0.0.1:${port}`, emit: () => {}, advance: () => {}, drop: () => {} }),
      ).rejects.toThrow(/expected an event stream/);
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });

  it("checks the body of an expected non-stream response", async () => {
    const { createServer } = await import("node:http");
    const server = createServer((_req, res) => {
      res.writeHead(404, { "Content-Type": "application/json" }).end('{"error":"other"}');
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    const port = (server.address() as { port: number }).port;
    const steps = [
      {
        step: "404 with a body",
        conn: "A",
        request: { method: "GET", path: "/wmp/events" },
        expect: { status: 404, body: { error: "session not found" } },
      },
    ];
    try {
      await expect(
        runTransportVector(steps, { baseUrl: `http://127.0.0.1:${port}`, emit: () => {}, advance: () => {}, drop: () => {} }),
      ).rejects.toThrow();
    } finally {
      server.closeAllConnections();
      await new Promise<void>((r) => server.close(() => r()));
    }
  });
});
