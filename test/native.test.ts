import { describe, it, expect, vi } from "vitest";
import { PassThrough } from "node:stream";
import { StdioTransport } from "../src/native.js";

describe("StdioTransport", () => {
  function createPair() {
    const input = new PassThrough();
    const output = new PassThrough();
    output.setEncoding("utf8");
    const transport = new StdioTransport({ input, output });
    return { transport, input, output };
  }

  it("emits open on construction", async () => {
    const { transport } = createPair();
    const open = vi.fn();
    transport.on("open", open);
    // open fires via queueMicrotask
    await new Promise((r) => setTimeout(r, 10));
    expect(open).toHaveBeenCalled();
    transport.close();
  });

  it("sends NDJSON messages", async () => {
    const { transport, output } = createPair();
    const chunks: string[] = [];
    output.on("data", (chunk: string) => chunks.push(chunk));

    await transport.send({ jsonrpc: "2.0", id: 1, method: "test", params: {} });
    expect(chunks).toHaveLength(1);
    const parsed = JSON.parse(chunks[0].trim());
    expect(parsed.method).toBe("test");
    expect(chunks[0].endsWith("\n")).toBe(true);
    transport.close();
  });

  it("receives NDJSON messages", async () => {
    const { transport, input } = createPair();
    const messages: unknown[] = [];
    transport.on("message", (msg) => messages.push(msg));

    // Write a complete JSON-RPC request
    input.write(
      JSON.stringify({ jsonrpc: "2.0", id: 1, method: "test", params: {} }) + "\n",
    );

    await new Promise((r) => setTimeout(r, 10));
    expect(messages).toHaveLength(1);
    expect((messages[0] as { method: string }).method).toBe("test");
    transport.close();
  });

  it("handles multiple messages in one chunk", async () => {
    const { transport, input } = createPair();
    const messages: unknown[] = [];
    transport.on("message", (msg) => messages.push(msg));

    const m1 = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "a", params: {} });
    const m2 = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "b", params: {} });
    input.write(m1 + "\n" + m2 + "\n");

    await new Promise((r) => setTimeout(r, 10));
    expect(messages).toHaveLength(2);
    transport.close();
  });

  it("handles messages split across chunks", async () => {
    const { transport, input } = createPair();
    const messages: unknown[] = [];
    transport.on("message", (msg) => messages.push(msg));

    const full = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "split", params: {} });
    // Split in the middle
    const mid = Math.floor(full.length / 2);
    input.write(full.substring(0, mid));
    await new Promise((r) => setTimeout(r, 5));
    expect(messages).toHaveLength(0);

    input.write(full.substring(mid) + "\n");
    await new Promise((r) => setTimeout(r, 10));
    expect(messages).toHaveLength(1);
    expect((messages[0] as { method: string }).method).toBe("split");
    transport.close();
  });

  it("emits close on input end", async () => {
    const { transport, input } = createPair();
    const close = vi.fn();
    transport.on("close", close);

    input.end();
    await new Promise((r) => setTimeout(r, 10));
    expect(close).toHaveBeenCalled();
  });

  it("rejects send after close", async () => {
    const { transport } = createPair();
    transport.close();
    await expect(
      transport.send({ jsonrpc: "2.0", id: 1, method: "x", params: {} }),
    ).rejects.toThrow("Transport is closed");
  });

  it("skips empty lines", async () => {
    const { transport, input } = createPair();
    const messages: unknown[] = [];
    transport.on("message", (msg) => messages.push(msg));

    input.write("\n\n" + JSON.stringify({ jsonrpc: "2.0", id: 1, method: "x", params: {} }) + "\n\n");
    await new Promise((r) => setTimeout(r, 10));
    expect(messages).toHaveLength(1);
    transport.close();
  });

  it("emits error on malformed JSON", async () => {
    const { transport, input } = createPair();
    const errors: Error[] = [];
    transport.on("error", (err) => errors.push(err));

    input.write("not-json\n");
    await new Promise((r) => setTimeout(r, 10));
    expect(errors).toHaveLength(1);
    transport.close();
  });
});
