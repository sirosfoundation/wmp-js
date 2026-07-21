/**
 * Transport interface and implementations — mirrors go-wmp/pkg/wmp/transport.go.
 *
 * Two transport implementations:
 *   - WebSocketTransport: bidirectional, persistent connection
 *   - HttpSseTransport: POST for sending + SSE EventSource for receiving
 */

import { type Message, decodeMessage } from "./jsonrpc.js";

// ---------------------------------------------------------------------------
// Transport interface
// ---------------------------------------------------------------------------

export interface TransportEvents {
  message: (msg: Message) => void;
  error: (err: Error) => void;
  close: () => void;
  open: () => void;
}

export type TransportEventName = keyof TransportEvents;

/**
 * Transport abstracts the underlying connection.
 * Mirrors go-wmp Transport but adapted for async JS.
 */
export interface Transport {
  /** Send a JSON-RPC message over the transport. */
  send(msg: Message): Promise<void>;

  /** Close the transport. */
  close(): void;

  /** Register an event listener. */
  on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;

  /** Remove an event listener. */
  off<K extends TransportEventName>(
    event: K,
    listener: TransportEvents[K],
  ): void;
}

// ---------------------------------------------------------------------------
// Simple EventEmitter for transports
// ---------------------------------------------------------------------------

type Listener = (...args: unknown[]) => void;

class Emitter {
  private listeners = new Map<string, Set<Listener>>();

  on(event: string, fn: Listener): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(fn);
  }

  off(event: string, fn: Listener): void {
    this.listeners.get(event)?.delete(fn);
  }

  protected emit(event: string, ...args: unknown[]): void {
    this.listeners.get(event)?.forEach((fn) => fn(...args));
  }
}

// ---------------------------------------------------------------------------
// WebSocket transport
// ---------------------------------------------------------------------------

export interface WebSocketTransportOptions {
  /** WebSocket subprotocol. Default: "wmp.v1" */
  protocols?: string | string[];
  /** Allow unencrypted ws:// URLs. Default: false. */
  allowInsecure?: boolean;
}

/**
 * WebSocket transport — bidirectional, persistent connection.
 * Works in browsers (native WebSocket) and Node.js (e.g., ws package).
 */
export class WebSocketTransport extends Emitter implements Transport {
  private ws: WebSocket;

  constructor(url: string, opts?: WebSocketTransportOptions) {
    super();
    const protocols = opts?.protocols ?? "wmp.v1";

    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new Error("Invalid WebSocket URL");
    }
    if (parsed.protocol !== "wss:" && parsed.protocol !== "ws:") {
      throw new Error(
        `Invalid WebSocket URL scheme: ${parsed.protocol}. Use ws:// or wss://`,
      );
    }
    if (parsed.protocol === "ws:" && !opts?.allowInsecure) {
      throw new Error(
        "Unencrypted ws:// WebSocket URLs are not allowed unless allowInsecure is true",
      );
    }

    this.ws = new WebSocket(url, protocols);

    this.ws.onopen = () => this.emit("open");
    this.ws.onclose = () => this.emit("close");
    this.ws.onerror = (ev) => {
      const err =
        ev instanceof ErrorEvent ? new Error(ev.message) : new Error("WebSocket error");
      this.emit("error", err);
    };
    this.ws.onmessage = (ev) => {
      try {
        const msg = decodeMessage(String(ev.data), { maxSize: 4 * 1024 * 1024 });
        this.emit("message", msg);
      } catch (err) {
        this.emit("error", err instanceof Error ? err : new Error(String(err)));
      }
    };
  }

  async send(msg: Message): Promise<void> {
    if (this.ws.readyState !== WebSocket.OPEN) {
      throw new Error("WebSocket is not open");
    }
    this.ws.send(JSON.stringify(msg));
  }

  close(): void {
    this.ws.close();
  }

  on<K extends TransportEventName>(
    event: K,
    listener: TransportEvents[K],
  ): void {
    super.on(event, listener as Listener);
  }

  off<K extends TransportEventName>(
    event: K,
    listener: TransportEvents[K],
  ): void {
    super.off(event, listener as Listener);
  }
}

// ---------------------------------------------------------------------------
// HTTP+SSE transport
// ---------------------------------------------------------------------------

export interface HttpSseTransportOptions {
  /** Authorization header value (e.g., "Bearer <token>"). */
  authorization?: string;
  /** Last-Event-ID for SSE replay. */
  lastEventId?: string;
  /** Custom fetch implementation (default: global fetch). */
  fetch?: typeof globalThis.fetch;
  /** Custom EventSource constructor (for polyfills that support headers). */
  EventSource?: typeof EventSource;
}

/**
 * HTTP+SSE transport — POST for outgoing, EventSource for incoming.
 *
 * POST endpoint receives JSON-RPC requests.
 * SSE endpoint streams server-initiated JSON-RPC notifications/responses.
 */
export class HttpSseTransport extends Emitter implements Transport {
  private rpcUrl: string;
  private eventsUrl: string;
  private authorization?: string;
  private sessionId?: string;
  private eventSource: EventSource | null = null;
  private fetchFn: typeof globalThis.fetch;
  private EventSourceCtor: typeof EventSource;
  private closed = false;

  constructor(
    rpcUrl: string,
    eventsUrl: string,
    opts?: HttpSseTransportOptions,
  ) {
    super();
    this.rpcUrl = rpcUrl;
    this.eventsUrl = eventsUrl;
    this.authorization = opts?.authorization;
    this.fetchFn = opts?.fetch ?? globalThis.fetch.bind(globalThis);
    this.EventSourceCtor = opts?.EventSource ?? globalThis.EventSource;
  }

  /**
   * Update the authorization header (e.g., after token refresh).
   * Takes effect on the next POST request.
   */
  setAuthorization(authorization: string): void {
    this.authorization = authorization;
  }

  /**
   * Bind a session ID to this transport. The session ID is sent as:
   * - `Wmp-Session-Id` header on POST requests (per WMP spec §4.5)
   * - `session_id` query parameter on SSE connections
   */
  setSessionId(sessionId: string): void {
    this.sessionId = sessionId;
  }

  /**
   * Connect the SSE stream. Call this after constructing the transport.
   * Separated from the constructor so callers can register listeners first.
   */
  connectSSE(lastEventId?: string): void {
    this.eventSource?.close();
    this.eventSource = null;

    this.setupEventSource(lastEventId);
  }

  /**
   * Reconnect the SSE stream with the current authorization/session state.
   * Useful after calling setAuthorization.
   */
  reconnectSSE(lastEventId?: string): void {
    this.connectSSE(lastEventId);
  }

  private setupEventSource(lastEventId?: string): void {
    // Build the SSE URL with session_id (required for tenant routing)
    // and optional lastEventId for event replay.
    let url = this.eventsUrl;
    if (this.sessionId) {
      const sep = url.includes("?") ? "&" : "?";
      url += `${sep}session_id=${encodeURIComponent(this.sessionId)}`;
    }
    if (lastEventId) {
      const sep = url.includes("?") ? "&" : "?";
      url += `${sep}lastEventId=${encodeURIComponent(lastEventId)}`;
    }

    this.eventSource = new this.EventSourceCtor(url);

    this.eventSource.onopen = () => this.emit("open");
    this.eventSource.onerror = () => {
      if (!this.closed) {
        this.emit("error", new Error("SSE connection error"));
      }
    };

    // WMP events use the "wmp" event type per the spec.
    this.eventSource.addEventListener("wmp", (ev) => {
      try {
        const msg = decodeMessage((ev as MessageEvent).data, { maxSize: 4 * 1024 * 1024 });
        this.emit("message", msg);
      } catch (err) {
        this.emit(
          "error",
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    });

    // Also handle default "message" events for compatibility.
    this.eventSource.onmessage = (ev) => {
      try {
        const msg = decodeMessage(ev.data, { maxSize: 4 * 1024 * 1024 });
        this.emit("message", msg);
      } catch (err) {
        this.emit(
          "error",
          err instanceof Error ? err : new Error(String(err)),
        );
      }
    };
  }

  async send(msg: Message): Promise<void> {
    if (this.closed) {
      throw new Error("Transport is closed");
    }

    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.authorization) {
      headers["Authorization"] = this.authorization;
    }
    if (this.sessionId) {
      headers["Wmp-Session-Id"] = this.sessionId;
    }

    const resp = await this.fetchFn(this.rpcUrl, {
      method: "POST",
      headers,
      body: JSON.stringify(msg),
    });

    if (!resp.ok) {
      throw new Error(`HTTP ${resp.status}: ${resp.statusText}`);
    }

    // If the server returns a JSON-RPC response in the POST body,
    // emit it as an incoming message.
    const ct = resp.headers.get("Content-Type") ?? "";
    if (ct.includes("application/json")) {
      const text = await resp.text();
      if (text.trim()) {
        try {
          const respMsg = decodeMessage(text);
          this.emit("message", respMsg);
        } catch {
          // Non-JSON-RPC body — ignore.
        }
      }
    }
  }

  close(): void {
    this.closed = true;
    this.eventSource?.close();
    this.eventSource = null;
    this.emit("close");
  }

  on<K extends TransportEventName>(
    event: K,
    listener: TransportEvents[K],
  ): void {
    super.on(event, listener as Listener);
  }

  off<K extends TransportEventName>(
    event: K,
    listener: TransportEvents[K],
  ): void {
    super.off(event, listener as Listener);
  }
}
