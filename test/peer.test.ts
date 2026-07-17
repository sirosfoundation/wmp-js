import { describe, it, expect, vi } from "vitest";
import { Peer, type Handler } from "../src/peer.js";
import type { Transport, TransportEvents, TransportEventName } from "../src/transport.js";
import type { Message } from "../src/jsonrpc.js";
import { createResponse, createRequest, createNotification } from "../src/jsonrpc.js";
import {
  Method,
  ErrorCode,
  type FlowStartParams,
  type FlowProgressParams,
  type SessionCreateParams,
  type SessionResumeParams,
  type SessionAuthenticateParams,
  type MessagePollParams,
  type CapabilityUpdateParams,
  type CapabilityListParams,
} from "../src/types.js";

// ---------------------------------------------------------------------------
// Mock transport — in-memory, synchronous
// ---------------------------------------------------------------------------

class MockTransport implements Transport {
  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  sent: Message[] = [];
  closed = false;

  async send(msg: Message): Promise<void> {
    this.sent.push(msg);
  }

  close(): void {
    this.closed = true;
  }

  on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as (...args: unknown[]) => void);
  }

  off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    this.listeners.get(event)?.delete(listener as (...args: unknown[]) => void);
  }

  /** Simulate receiving a message from the remote side. */
  receive(msg: Message): void {
    this.listeners.get("message")?.forEach((fn) => fn(msg));
  }

  /** Simulate transport close. */
  simulateClose(): void {
    this.listeners.get("close")?.forEach((fn) => fn());
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("Peer", () => {
  it("sends a call and resolves on response", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const callPromise = peer.call("wmp.session.create", { wmp: { version: "0.1" } });

    // The transport should have the outgoing request.
    expect(transport.sent).toHaveLength(1);
    const req = transport.sent[0] as { id: string; method: string };
    expect(req.method).toBe("wmp.session.create");

    // Simulate the response.
    transport.receive(
      createResponse(req.id, {
        wmp: { version: "0.1", session_id: "ses-123" },
        security: { mode: "tls" },
      }),
    );

    const result = await callPromise;
    expect((result as { wmp: { session_id: string } }).wmp.session_id).toBe("ses-123");
  });

  it("rejects a call on error response", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const callPromise = peer.call("wmp.session.create", {});
    const req = transport.sent[0] as { id: string };

    transport.receive({
      jsonrpc: "2.0",
      id: req.id,
      error: { code: ErrorCode.NotAuthorized, message: "Not authorized" },
    });

    await expect(callPromise).rejects.toThrow("Not authorized");
  });

  it("dispatches incoming request to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onFlowStart: vi.fn(async (params: FlowStartParams) => ({
        wmp: params.wmp,
        flow_id: params.flow_id,
        flow_type: params.flow_type,
      })),
    };
    new Peer(transport, { handler });

    // Simulate incoming flow.start request.
    transport.receive(
      createRequest(Method.FlowStart, {
        wmp: { version: "0.1", session_id: "ses-1" },
        flow_type: "approval",
        flow_id: "flow-1",
      }) as Message,
    );

    // Wait for async dispatch.
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onFlowStart).toHaveBeenCalled();
    // Response should be sent back.
    expect(transport.sent).toHaveLength(1);
    const resp = transport.sent[0] as { result: { flow_id: string } };
    expect(resp.result.flow_id).toBe("flow-1");
  });

  it("dispatches notifications to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onFlowProgress: vi.fn(),
    };
    new Peer(transport, { handler });

    transport.receive(
      createNotification(Method.FlowProgress, {
        wmp: { version: "0.1", session_id: "ses-1" },
        flow_id: "flow-1",
        step: "processing",
      }) as Message,
    );

    await new Promise((r) => setTimeout(r, 10));
    expect(handler.onFlowProgress).toHaveBeenCalledWith(
      expect.objectContaining({ flow_id: "flow-1", step: "processing" }),
    );

    // No response for notifications.
    expect(transport.sent).toHaveLength(0);
  });

  it("returns method-not-found for unhandled methods", async () => {
    const transport = new MockTransport();
    new Peer(transport);

    transport.receive(
      createRequest("wmp.unknown.method", {}) as Message,
    );

    await new Promise((r) => setTimeout(r, 10));
    expect(transport.sent).toHaveLength(1);
    const resp = transport.sent[0] as { error: { code: number } };
    expect(resp.error.code).toBe(ErrorCode.MethodNotFound);
  });

  it("rejects pending calls on close", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const callPromise = peer.call("wmp.session.create", {});
    peer.close();

    await expect(callPromise).rejects.toThrow("Peer closed");
    expect(transport.closed).toBe(true);
  });

  it("rejects pending calls on transport close", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const callPromise = peer.call("wmp.session.create", {});
    transport.simulateClose();

    await expect(callPromise).rejects.toThrow("Transport closed");
  });

  it("createSession sets sessionId", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    const promise = peer.createSession({ security: { mode: "tls" } });
    const req = transport.sent[0] as { id: string };

    transport.receive(
      createResponse(req.id, {
        wmp: { version: "0.1", session_id: "ses-abc" },
        security: { mode: "tls" },
      }),
    );

    await promise;
    expect(peer.session).toBe("ses-abc");
  });

  it("createSession calls setSessionId on transport when available", async () => {
    const transport = new MockTransport();
    const setSessionId = vi.fn();
    (transport as unknown as { setSessionId: typeof setSessionId }).setSessionId = setSessionId;

    const peer = new Peer(transport);
    const promise = peer.createSession({ security: { mode: "tls" } });
    const req = transport.sent[0] as { id: string };

    transport.receive(
      createResponse(req.id, {
        wmp: { version: "0.1", session_id: "ses-bound" },
        security: { mode: "tls" },
      }),
    );

    await promise;
    expect(setSessionId).toHaveBeenCalledWith("ses-bound");
  });

  it("notify sends a notification", async () => {
    const transport = new MockTransport();
    const peer = new Peer(transport);

    await peer.notify(Method.FlowProgress, {
      wmp: { version: "0.1" },
      flow_id: "f1",
      step: "done",
    });

    expect(transport.sent).toHaveLength(1);
    const msg = transport.sent[0] as { id?: string; method: string };
    expect(msg.id).toBeUndefined();
    expect(msg.method).toBe(Method.FlowProgress);
  });

  // -------------------------------------------------------------------------
  // Tests for newly-added dispatch paths (alignment with go-wmp)
  // -------------------------------------------------------------------------

  it("dispatches session.resume to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onSessionResume: vi.fn(async (p: SessionResumeParams) => ({
        wmp: { version: "0.1", session_id: p.session_id },
        resumed: true,
        missed_messages: 0,
        security: { mode: "tls" },
      })),
    };
    new Peer(transport, { handler });

    transport.receive(
      createRequest(Method.SessionResume, {
        wmp: { version: "0.1" },
        session_id: "ses-1",
        resumption_token: "tok-1",
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onSessionResume).toHaveBeenCalled();
    expect(transport.sent).toHaveLength(1);
    expect((transport.sent[0] as { result: { resumed: boolean } }).result.resumed).toBe(true);
  });

  it("dispatches session.authenticate to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onSessionAuthenticate: vi.fn(async () => ({
        wmp: { version: "0.1" },
        authenticated: true,
        identity: "did:web:example.com",
      })),
    };
    new Peer(transport, { handler });

    transport.receive(
      createRequest(Method.SessionAuthenticate, {
        wmp: { version: "0.1" },
        auth: { type: "bearer", token: "tok" },
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onSessionAuthenticate).toHaveBeenCalled();
    const resp = transport.sent[0] as { result: { authenticated: boolean } };
    expect(resp.result.authenticated).toBe(true);
  });

  it("dispatches message.deliver notification to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onMessageDeliver: vi.fn(),
    };
    new Peer(transport, { handler });

    transport.receive(
      createNotification(Method.MessageDeliver, {
        wmp: { version: "0.1", session_id: "ses-1" },
        content_type: "text/plain",
        body: "hello",
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onMessageDeliver).toHaveBeenCalled();
    expect(transport.sent).toHaveLength(0); // notification, no response
  });

  it("dispatches message.ack notification to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onMessageAck: vi.fn(),
    };
    new Peer(transport, { handler });

    transport.receive(
      createNotification(Method.MessageAck, {
        wmp: { version: "0.1" },
        message_ids: ["m1"],
        status: "received",
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onMessageAck).toHaveBeenCalled();
  });

  it("dispatches message.poll request to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onMessagePoll: vi.fn(async () => ({
        wmp: { version: "0.1" },
        messages: [{ id: "m1" }],
      })),
    };
    new Peer(transport, { handler });

    transport.receive(
      createRequest(Method.MessagePoll, {
        wmp: { version: "0.1" },
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onMessagePoll).toHaveBeenCalled();
    const resp = transport.sent[0] as { result: { messages: unknown[] } };
    expect(resp.result.messages).toHaveLength(1);
  });

  it("dispatches message.status notification to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onMessageStatus: vi.fn(),
    };
    new Peer(transport, { handler });

    transport.receive(
      createNotification(Method.MessageStatus, {
        wmp: { version: "0.1" },
        message_id: "m1",
        status: "delivered",
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onMessageStatus).toHaveBeenCalled();
  });

  it("dispatches capability.update request to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onCapabilityUpdate: vi.fn(async () => ({
        wmp: { version: "0.1" },
        capabilities: { messaging: {} },
        security: { mode: "tls" },
      })),
    };
    new Peer(transport, { handler });

    transport.receive(
      createRequest(Method.CapabilityUpdate, {
        wmp: { version: "0.1" },
        add: { relay: {} },
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onCapabilityUpdate).toHaveBeenCalled();
    expect(transport.sent).toHaveLength(1);
  });

  it("dispatches capability.list request to handler", async () => {
    const transport = new MockTransport();
    const handler: Handler = {
      onCapabilityList: vi.fn(async () => ({
        wmp: { version: "0.1" },
        capabilities: {},
        security: { mode: "tls" },
      })),
    };
    new Peer(transport, { handler });

    transport.receive(
      createRequest(Method.CapabilityList, {
        wmp: { version: "0.1" },
      }) as Message,
    );
    await new Promise((r) => setTimeout(r, 10));

    expect(handler.onCapabilityList).toHaveBeenCalled();
    expect(transport.sent).toHaveLength(1);
  });
});
