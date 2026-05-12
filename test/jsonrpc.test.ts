import { describe, it, expect } from "vitest";
import {
  createRequest,
  createNotification,
  createResponse,
  createErrorResponse,
  decodeMessage,
  decodeBatch,
  isRequest,
  isResponse,
  isNotification,
  resetRequestIdCounter,
  WMPError,
} from "../src/jsonrpc.js";

describe("createRequest", () => {
  it("creates a valid JSON-RPC 2.0 request", () => {
    resetRequestIdCounter();
    const req = createRequest("wmp.session.create", { foo: 1 });
    expect(req.jsonrpc).toBe("2.0");
    expect(req.id).toBe("req-1");
    expect(req.method).toBe("wmp.session.create");
    expect(req.params).toEqual({ foo: 1 });
  });

  it("increments IDs", () => {
    resetRequestIdCounter();
    const r1 = createRequest("a", {});
    const r2 = createRequest("b", {});
    expect(r1.id).toBe("req-1");
    expect(r2.id).toBe("req-2");
  });
});

describe("createNotification", () => {
  it("creates a notification with no id", () => {
    const n = createNotification("wmp.flow.progress", { step: "x" });
    expect(n.id).toBeUndefined();
    expect(n.method).toBe("wmp.flow.progress");
  });
});

describe("createResponse / createErrorResponse", () => {
  it("creates a success response", () => {
    const r = createResponse("req-1", { ok: true });
    expect(r.jsonrpc).toBe("2.0");
    expect(r.id).toBe("req-1");
    expect(r.result).toEqual({ ok: true });
    expect(r.error).toBeUndefined();
  });

  it("creates an error response", () => {
    const r = createErrorResponse("req-1", {
      code: -32601,
      message: "Method not found",
    });
    expect(r.error?.code).toBe(-32601);
    expect(r.result).toBeUndefined();
  });
});

describe("decodeMessage", () => {
  it("decodes a request", () => {
    const msg = decodeMessage(
      '{"jsonrpc":"2.0","id":"1","method":"wmp.session.create","params":{}}',
    );
    expect(isRequest(msg)).toBe(true);
    expect(isResponse(msg)).toBe(false);
  });

  it("decodes a response", () => {
    const msg = decodeMessage(
      '{"jsonrpc":"2.0","id":"1","result":{"ok":true}}',
    );
    expect(isResponse(msg)).toBe(true);
    expect(isRequest(msg)).toBe(false);
  });

  it("decodes an error response", () => {
    const msg = decodeMessage(
      '{"jsonrpc":"2.0","id":"1","error":{"code":-32601,"message":"not found"}}',
    );
    expect(isResponse(msg)).toBe(true);
  });

  it("rejects invalid JSON-RPC version", () => {
    expect(() => decodeMessage('{"jsonrpc":"1.0","method":"x","params":{}}')).toThrow(
      "Invalid JSON-RPC version",
    );
  });

  it("rejects invalid JSON", () => {
    expect(() => decodeMessage("not json")).toThrow();
  });
});

describe("decodeBatch", () => {
  it("decodes a batch of messages", () => {
    const msgs = decodeBatch(
      '[{"jsonrpc":"2.0","id":"1","method":"a","params":{}},{"jsonrpc":"2.0","id":"2","method":"b","params":{}}]',
    );
    expect(msgs).toHaveLength(2);
    expect(isRequest(msgs[0])).toBe(true);
  });

  it("wraps single message in array", () => {
    const msgs = decodeBatch('{"jsonrpc":"2.0","id":"1","method":"a","params":{}}');
    expect(msgs).toHaveLength(1);
  });
});

describe("isNotification", () => {
  it("returns true for requests without id", () => {
    const n = createNotification("x", {});
    expect(isNotification(n)).toBe(true);
  });

  it("returns false for requests with id", () => {
    resetRequestIdCounter();
    const r = createRequest("x", {});
    expect(isNotification(r)).toBe(false);
  });
});

describe("WMPError", () => {
  it("formats error message", () => {
    const e = new WMPError(-31000, "Session not found");
    expect(e.code).toBe(-31000);
    expect(e.message).toContain("-31000");
    expect(e.name).toBe("WMPError");
  });

  it("converts to RPCError", () => {
    const e = new WMPError(-31006, "Flow error", { retry: true });
    const rpc = e.toRPCError();
    expect(rpc.code).toBe(-31006);
    expect(rpc.data).toEqual({ retry: true });
  });
});
