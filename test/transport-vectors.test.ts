/**
 * Executes every transport-http vector over real HTTP against the in-repo
 * server stub (test/support/sse-stub.ts). go-wmp's secured server is not
 * released yet; this is the executor wmp-js and the stub are both checked by.
 */
import { describe, it, afterEach } from "vitest";
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
