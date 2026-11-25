import { describe, it, expect, vi, afterEach } from "vitest";
import { HttpSseTransport } from "../src/transport.js";

describe("HttpSseTransport without an EventSource", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("says an EventSource must be supplied when the stream is opened", () => {
    vi.stubGlobal("EventSource", undefined);
    const transport = new HttpSseTransport("https://example.com/wmp", "https://example.com/wmp/events");
    expect(() => transport.connectSSE()).toThrow(/opts\.EventSource/);
  });

  it("opens the stream with the supplied EventSource", () => {
    vi.stubGlobal("EventSource", undefined);
    const opened: string[] = [];
    class Stub {
      onopen = null;
      onerror = null;
      onmessage = null;
      readyState = 0;
      constructor(url: string) {
        opened.push(url);
      }
      addEventListener(): void {}
      close(): void {}
    }
    const transport = new HttpSseTransport("https://example.com/wmp", "https://example.com/wmp/events", {
      EventSource: Stub as unknown as typeof EventSource,
    });
    transport.connectSSE();
    expect(opened).toEqual(["https://example.com/wmp/events"]);
  });
});
