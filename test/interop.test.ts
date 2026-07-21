/**
 * Interoperability tests — run the shared WMP test vectors against wmp-js
 * and assert that responses match the expected cross-implementation output.
 *
 * Vectors live in wmp/vectors/interop.json and are also consumed by
 * go-wmp/pkg/wmp/interop_test.go.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { Peer, type Handler } from "../src/peer.js";
import type { Transport, TransportEvents, TransportEventName } from "../src/transport.js";
import { WMPError, type Message, type Request, type Response, type RPCError } from "../src/jsonrpc.js";
import { Method, ErrorCode } from "../src/types.js";

// ---------------------------------------------------------------------------
// Test vector types
// ---------------------------------------------------------------------------

interface HandlerAction {
  method: string;
  return?: unknown;
  error?: RPCError;
}

interface PeerOptionsConfig {
  authorize?: boolean;
  validate?: boolean;
}

interface InteropVector {
  id: string;
  description: string;
  conformance_level: string;
  input: Request;
  expected_response?: unknown;
  expected_error?: Response;
  handler_action?: HandlerAction;
  peer_options?: PeerOptionsConfig;
  notes?: string;
}

function loadInteropVectors(): InteropVector[] {
  const path = resolve(__dirname, "../../wmp/vectors/interop.json");
  const data = readFileSync(path, "utf8");
  return JSON.parse(data) as InteropVector[];
}

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

  receive(msg: Message): void {
    this.listeners.get("message")?.forEach((fn) => fn(msg));
  }
}

// ---------------------------------------------------------------------------
// Handler builder driven by vector instructions
// ---------------------------------------------------------------------------

function buildHandler(action?: HandlerAction): Handler {
  return {
    onResolve: async (_params) => {
      if (action?.method !== Method.Resolve) {
        return undefined as unknown as { wmp: unknown; type: string; uri: string; metadata: unknown };
      }
      if (action.error) {
        throw new WMPError(action.error.code, action.error.message, action.error.data);
      }
      return action.return as { wmp: unknown; type: string; uri: string; metadata: unknown };
    },
  };
}

// ---------------------------------------------------------------------------
// Comparison helpers
// ---------------------------------------------------------------------------

function normalize(value: unknown): unknown {
  return JSON.parse(JSON.stringify(value));
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const vectors = loadInteropVectors();

describe("Interop vectors", () => {
  for (const v of vectors) {
    it(`${v.id}: ${v.description}`, async () => {
      const transport = new MockTransport();
      const handler = buildHandler(v.handler_action);

      const peerOpts: ConstructorParameters<typeof Peer>[1] = { handler };
      if (v.peer_options?.authorize === false) {
        peerOpts.authorize = () => false;
      }
      if (v.peer_options?.validate === false) {
        peerOpts.validator = {
          validateMethod: () => [{ path: "", message: "rejected by test validator" }],
        };
      }

      new Peer(transport, peerOpts);

      transport.receive(v.input);

      // Allow async dispatch to settle.
      await new Promise((resolve) => setTimeout(resolve, 10));

      // Notification with no expected response.
      if (v.expected_response === null) {
        expect(transport.sent, `${v.id}: notifications must not produce a response`).toHaveLength(0);
        return;
      }

      if (v.expected_error) {
        expect(transport.sent, `${v.id}: expected an error response`).toHaveLength(1);
        const resp = transport.sent[0] as Response;
        expect(resp.error, `${v.id}: response must contain error`).toBeDefined();
        expect(resp.error!.code, `${v.id}: error code mismatch`).toBe(v.expected_error.error!.code);
        expect(resp.error!.message, `${v.id}: error message must be non-empty`).toEqual(expect.any(String));
        return;
      }

      if (v.expected_response) {
        expect(transport.sent, `${v.id}: expected a success response`).toHaveLength(1);
        const resp = transport.sent[0] as Response;
        expect(resp.error, `${v.id}: response must not contain error`).toBeUndefined();
        expect(normalize(resp), `${v.id}: full response mismatch`).toEqual(normalize(v.expected_response));
        return;
      }

      expect(transport.sent, `${v.id}: expected no response`).toHaveLength(0);
    });
  }
});
