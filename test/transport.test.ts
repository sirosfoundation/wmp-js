import { describe, it, expect, vi } from "vitest";
import { HttpSseTransport } from "../src/transport.js";
import { createRequest } from "../src/jsonrpc.js";

describe("HttpSseTransport", () => {
  describe("session ID binding", () => {
    it("sends Wmp-Session-Id header on POST after setSessionId", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers(),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        { fetch: fetchMock as unknown as typeof fetch },
      );

      transport.setSessionId("ses-123");

      const req = createRequest("wmp.flow.start", { flow_id: "f1" });
      await transport.send(req);

      expect(fetchMock).toHaveBeenCalledOnce();
      const [, init] = fetchMock.mock.calls[0];
      expect(init.headers["Wmp-Session-Id"]).toBe("ses-123");
    });

    it("does not send Wmp-Session-Id when no session is bound", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers(),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        { fetch: fetchMock as unknown as typeof fetch },
      );

      const req = createRequest("wmp.session.create", {});
      await transport.send(req);

      const [, init] = fetchMock.mock.calls[0];
      expect(init.headers["Wmp-Session-Id"]).toBeUndefined();
    });
  });

  describe("authorization", () => {
    it("sends Authorization header on POST", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers(),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        {
          authorization: "Bearer jwt-token-1",
          fetch: fetchMock as unknown as typeof fetch,
        },
      );

      await transport.send(createRequest("wmp.session.create", {}));

      const [, init] = fetchMock.mock.calls[0];
      expect(init.headers["Authorization"]).toBe("Bearer jwt-token-1");
    });

    it("setAuthorization updates the token for subsequent requests", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers(),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        {
          authorization: "Bearer old-token",
          fetch: fetchMock as unknown as typeof fetch,
        },
      );

      transport.setAuthorization("Bearer new-token");
      await transport.send(createRequest("wmp.flow.start", {}));

      const [, init] = fetchMock.mock.calls[0];
      expect(init.headers["Authorization"]).toBe("Bearer new-token");
    });
  });

  describe("POST response handling", () => {
    it("emits JSON-RPC response from POST body", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: true,
        headers: new Headers({ "Content-Type": "application/json" }),
        text: () =>
          Promise.resolve(
            '{"jsonrpc":"2.0","id":"req-1","result":{"wmp":{"session_id":"ses-1"}}}',
          ),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        { fetch: fetchMock as unknown as typeof fetch },
      );

      const messages: unknown[] = [];
      transport.on("message", (msg) => messages.push(msg));

      await transport.send(createRequest("wmp.session.create", {}));

      expect(messages).toHaveLength(1);
      expect((messages[0] as { result: { wmp: { session_id: string } } }).result.wmp.session_id).toBe("ses-1");
    });

    it("throws on non-ok HTTP response", async () => {
      const fetchMock = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        statusText: "Unauthorized",
        headers: new Headers(),
      });

      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
        { fetch: fetchMock as unknown as typeof fetch },
      );

      await expect(
        transport.send(createRequest("wmp.session.create", {})),
      ).rejects.toThrow("HTTP 401");
    });
  });

  describe("close", () => {
    it("prevents sending after close", async () => {
      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
      );

      transport.close();

      await expect(
        transport.send(createRequest("wmp.session.create", {})),
      ).rejects.toThrow("Transport is closed");
    });

    it("emits close event", () => {
      const transport = new HttpSseTransport(
        "https://example.com/wmp",
        "https://example.com/wmp/events",
      );

      const closeFn = vi.fn();
      transport.on("close", closeFn);
      transport.close();
      expect(closeFn).toHaveBeenCalledOnce();
    });
  });
});
