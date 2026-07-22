import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
  decodeMessage,
  decodeBatch,
  createRequest,
} from "../src/jsonrpc.js";
import { Peer } from "../src/peer.js";
import { WebSocketTransport } from "../src/transport.js";
import { StdioTransport } from "../src/native.js";
import { NoopMLSProvider } from "../src/mls.js";
import { createInvitation, verifyInvitation } from "../src/invitation.js";
import { extractDomain } from "../src/discovery.js";
import { OpenID4xProfile } from "../src/openid4x.js";
import { join } from "node:path";
import { createValidator } from "../src/schema.js";
import { MockTransport } from "./mock-transport.js";

const SCHEMA_DIR = join(__dirname, "..", "..", "wmp", "schema");
import type { Request } from "../src/jsonrpc.js";
import { Method, ErrorCode } from "../src/types.js";

// ---------------------------------------------------------------------------
// JSON-RPC decoding bounds
// ---------------------------------------------------------------------------

describe("decodeMessage bounds", () => {
  it("rejects payloads exceeding maxSize", () => {
    const big = JSON.stringify({ jsonrpc: "2.0", id: "x", result: "a".repeat(100) });
    expect(() => decodeMessage(big, { maxSize: 50 })).toThrow(
      "exceeds maximum size",
    );
  });

  it("rejects payloads exceeding maxDepth", () => {
    const nested = { jsonrpc: "2.0", id: "x", result: {} as unknown };
    let cursor: Record<string, unknown> = nested.result as Record<string, unknown>;
    for (let i = 0; i < 40; i++) {
      cursor.nested = {};
      cursor = cursor.nested as Record<string, unknown>;
    }
    expect(() => decodeMessage(JSON.stringify(nested), { maxDepth: 16 })).toThrow(
      "maximum nesting depth",
    );
  });

  it("decodes valid messages within bounds", () => {
    const msg = '{"jsonrpc":"2.0","id":"x","result":true}';
    const decoded = decodeMessage(msg, { maxSize: 100, maxDepth: 4 });
    expect(decoded.jsonrpc).toBe("2.0");
  });
});

describe("decodeBatch bounds", () => {
  it("rejects batched payloads exceeding maxSize", () => {
    const batch = JSON.stringify([
      { jsonrpc: "2.0", id: "x", result: "a".repeat(100) },
    ]);
    expect(() => decodeBatch(batch, { maxSize: 50 })).toThrow(
      "exceeds maximum size",
    );
  });

  it("decodes valid batched messages", () => {
    const batch = '[{"jsonrpc":"2.0","id":"x","result":true}]';
    expect(decodeBatch(batch)).toHaveLength(1);
  });
});

describe("createRequest random IDs", () => {
  it("uses cryptographically random IDs", () => {
    const ids = new Set<string>();
    for (let i = 0; i < 50; i++) {
      const req = createRequest("x", {}) as { id: string };
      expect(req.id).toMatch(/^req-[A-Za-z0-9_-]+$/);
      expect(ids.has(req.id)).toBe(false);
      ids.add(req.id);
    }
  });
});

// ---------------------------------------------------------------------------
// Peer validation and authorization
// ---------------------------------------------------------------------------

describe("Peer security hooks", () => {
  it("validates incoming requests when validator is configured", async () => {
    const transport = new MockTransport();
    const handler = { onFlowStart: vi.fn(async () => ({ ok: true })) };
    const validator = {
      validateMethod: vi.fn(() => [
        { path: "/flow_id", message: "required" },
      ]),
    };
    new Peer(transport, { handler, validator });

    transport.receive({
      jsonrpc: "2.0",
      id: "req-1",
      method: Method.FlowStart,
      params: {},
    } as Request);

    await new Promise((r) => setTimeout(r, 10));

    const resp = transport.sent[0] as { error: { code: number; message: string } };
    expect(resp.error.code).toBe(ErrorCode.InvalidParams);
    expect(resp.error.message).toContain("required");
    expect(handler.onFlowStart).not.toHaveBeenCalled();
  });

  it("rejects unauthorized requests", async () => {
    const transport = new MockTransport();
    const handler = { onFlowStart: vi.fn(async () => ({ ok: true })) };
    const authorize = vi.fn(() => false);
    new Peer(transport, { handler, authorize });

    transport.receive({
      jsonrpc: "2.0",
      id: "req-2",
      method: Method.FlowStart,
      params: { wmp: {}, flow_type: "x", flow_id: "f1" },
    } as Request);

    await new Promise((r) => setTimeout(r, 10));

    const resp = transport.sent[0] as { error: { code: number } };
    expect(resp.error.code).toBe(ErrorCode.NotAuthorized);
    expect(handler.onFlowStart).not.toHaveBeenCalled();
  });

  it("sanitizes unexpected handler errors", async () => {
    const transport = new MockTransport();
    const handler = {
      onFlowStart: vi.fn(async () => {
        throw new Error("internal database password: secret123");
      }),
    };
    new Peer(transport, { handler });

    transport.receive({
      jsonrpc: "2.0",
      id: "req-3",
      method: Method.FlowStart,
      params: { wmp: {}, flow_type: "x", flow_id: "f1" },
    } as Request);

    await new Promise((r) => setTimeout(r, 10));

    const resp = transport.sent[0] as { error: { code: number; message: string } };
    expect(resp.error.code).toBe(ErrorCode.InternalError);
    expect(resp.error.message).toBe("Internal error");
    expect(resp.error.message).not.toContain("secret123");
  });

  it("rejects session.create responses missing session_id", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const promise = peer.createSession({ security: { mode: "tls" } });
    const req = transport.sent[0] as { id: string };
    transport.receive({
      jsonrpc: "2.0",
      id: req.id,
      result: { wmp: { version: "0.1" }, security: { mode: "tls" } },
    });

    await expect(promise).rejects.toMatchObject({
      code: ErrorCode.SessionNotFound,
    });
  });

  it("rejects session.create responses with unsupported version", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const promise = peer.createSession({ security: { mode: "tls" } });
    const req = transport.sent[0] as { id: string };
    transport.receive({
      jsonrpc: "2.0",
      id: req.id,
      result: {
        wmp: { version: "99.0", session_id: "s1" },
        security: { mode: "tls" },
      },
    });

    await expect(promise).rejects.toMatchObject({
      code: ErrorCode.VersionNotSupported,
    });
  });
});

// ---------------------------------------------------------------------------
// WebSocket transport URL validation
// ---------------------------------------------------------------------------

describe("WebSocketTransport URL validation", () => {
  const originalWebSocket = globalThis.WebSocket;

  beforeEach(() => {
    // @ts-expect-error minimal mock for URL validation tests
    globalThis.WebSocket = vi.fn();
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
  });

  it("rejects non-WebSocket schemes", () => {
    expect(
      () => new WebSocketTransport("https://example.com/ws"),
    ).toThrow("Invalid WebSocket URL scheme");
  });

  it("rejects unencrypted ws:// by default", () => {
    expect(
      () => new WebSocketTransport("ws://example.com/ws"),
    ).toThrow("Unencrypted ws://");
  });

  it("allows ws:// when allowInsecure is true", () => {
    expect(
      () => new WebSocketTransport("ws://example.com/ws", { allowInsecure: true }),
    ).not.toThrow();
  });

  it("allows wss://", () => {
    expect(
      () => new WebSocketTransport("wss://example.com/ws"),
    ).not.toThrow();
  });
});

// ---------------------------------------------------------------------------
// Native transport line limits
// ---------------------------------------------------------------------------

describe("StdioTransport line limits", () => {
  it("closes when a line exceeds maxLineLength", async () => {
    const input = new (await import("node:stream")).Readable({
      read() {},
    });
    const output = new (await import("node:stream")).Writable({
      write(_chunk, _enc, cb) {
        cb();
      },
    });

    const errorHandler = vi.fn();
    const closeHandler = vi.fn();
    const transport = new StdioTransport({
      input,
      output,
      maxLineLength: 20,
    });
    transport.on("error", errorHandler);
    transport.on("close", closeHandler);

    input.push("a".repeat(50));
    await new Promise((r) => setTimeout(r, 10));

    expect(errorHandler).toHaveBeenCalledWith(
      expect.objectContaining({ message: "Native transport line exceeds maximum length" }),
    );
    expect(closeHandler).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// NoopMLSProvider requires explicit opt-in
// ---------------------------------------------------------------------------

describe("NoopMLSProvider", () => {
  it("refuses to instantiate without explicitlyInsecure", () => {
    expect(() => new NoopMLSProvider({} as { explicitlyInsecure: true })).toThrow(
      "explicitlyInsecure: true",
    );
  });

  it("instantiates with explicitlyInsecure: true", () => {
    const provider = new NoopMLSProvider({ explicitlyInsecure: true });
    expect(provider).toBeDefined();
  });
});

// ---------------------------------------------------------------------------
// Invitation verification
// ---------------------------------------------------------------------------

describe("verifyInvitation", () => {
  it("rejects expired invitations", async () => {
    const inv = createInvitation({
      provider: "https://example.com",
      sender: "did:web:example.com",
      ttl: -1,
    });
    inv.signature = "sig";
    await expect(
      verifyInvitation(inv, async () => true),
    ).rejects.toThrow("invitation expired");
  });

  it("rejects missing signatures", async () => {
    const inv = createInvitation({
      provider: "https://example.com",
      sender: "did:web:example.com",
    });
    await expect(
      verifyInvitation(inv, async () => true),
    ).rejects.toThrow("invitation missing signature");
  });

  it("rejects invalid signatures", async () => {
    const inv = createInvitation({
      provider: "https://example.com",
      sender: "did:web:example.com",
    });
    inv.signature = "sig";
    await expect(
      verifyInvitation(inv, async () => false),
    ).rejects.toThrow("signature verification failed");
  });

  it("accepts valid signatures", async () => {
    const inv = createInvitation({
      provider: "https://example.com",
      sender: "did:web:example.com",
    });
    inv.signature = "sig";
    const result = await verifyInvitation(inv, async () => true);
    expect(result.nonce).toBe(inv.nonce);
  });
});

// ---------------------------------------------------------------------------
// Discovery domain validation
// ---------------------------------------------------------------------------

describe("extractDomain validation", () => {
  it("rejects malformed did:web identifiers", () => {
    expect(extractDomain("did:web:")).toBe("");
    expect(extractDomain("did:web:..")).toBe("");
    expect(extractDomain("did:web:foo..bar")).toBe("");
    expect(
      extractDomain("did:web:" + "a".repeat(300)),
    ).toBe("");
  });

  it("accepts valid did:web identifiers", () => {
    expect(extractDomain("did:web:example.com")).toBe("example.com");
    expect(extractDomain("did:web:example.com:user:alice")).toBe("example.com");
  });
});

// ---------------------------------------------------------------------------
// Schema validator strict mode
// ---------------------------------------------------------------------------

describe("createValidator strict mode", () => {
  it("returns null for unknown methods by default", async () => {
    const validator = createValidator(SCHEMA_DIR);
    expect(validator.validateMethod("unknown.method", {})).toBeNull();
  });

  it("returns an error for unknown methods in strict mode", async () => {
    const validator = createValidator(SCHEMA_DIR, true);
    const errors = validator.validateMethod("unknown.method", {});
    expect(errors).not.toBeNull();
    expect(errors?.[0].message).toContain("No schema defined");
  });
});

// ---------------------------------------------------------------------------
// OpenID4x credential notification validation
// ---------------------------------------------------------------------------

describe("OpenID4xProfile credential notification", () => {
  it("rejects unknown notification_ids by default", async () => {
    const profile = new OpenID4xProfile({
      oid4vci: {
        supported_grants: ["authorization_code"],
        supported_formats: ["vc+sd-jwt"],
      },
    });

    await expect(
      profile.handleMethod(Method.CredentialNotification, {
        wmp: { version: "0.1" },
        flow_id: "flow-1",
        notification_id: "nid-1",
        event_type: "credential_accepted",
        evidence_id: "e1",
        evidence_version: "1",
        timestamp: new Date().toISOString(),
      }),
    ).rejects.toMatchObject({ code: ErrorCode.NotAuthorized });
  });

  it("accepts registered notification_ids", async () => {
    const profile = new OpenID4xProfile({
      oid4vci: {
        supported_grants: ["authorization_code"],
        supported_formats: ["vc+sd-jwt"],
      },
    });
    profile.registerCredentialNotification("flow-1", "nid-1");

    const result = await profile.handleMethod(Method.CredentialNotification, {
      wmp: { version: "0.1" },
      flow_id: "flow-1",
      notification_id: "nid-1",
      event_type: "credential_accepted",
      evidence_id: "e1",
      evidence_version: "1",
      timestamp: new Date().toISOString(),
    });

    expect((result as { acknowledged: boolean }).acknowledged).toBe(true);
  });

  it("does not expose methods when oid4vci is disabled", () => {
    const profile = new OpenID4xProfile({
      oid4vp: {
        supported_response_modes: ["direct_post"],
        supported_formats: ["vc+sd-jwt"],
      },
    });
    expect(profile.methods()).toEqual([]);
  });
});
