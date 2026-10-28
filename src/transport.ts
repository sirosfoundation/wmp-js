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
  /**
   * The server answered a reconnect with 410 (Transport Section 4.3.4): events
   * were lost. The transport has already discarded its cursor and opened a new
   * stream with none; the application (Peer) now resumes the session.
   */
  gap: () => void;
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
  /**
   * Initial SSE cursor (the ID of the last event already processed). It is
   * sent on the first connectSSE() and replaces itself as events arrive.
   */
  lastEventId?: string;
  /** How many processed event IDs to remember for replay dedupe. Default: 4096. */
  dedupeWindow?: number;
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
  private cursor?: string;
  private seenIds = new Set<string>();
  private dedupeWindow: number;
  private pendingGap = false;

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
    this.cursor = opts?.lastEventId || undefined;
    this.dedupeWindow = opts?.dedupeWindow ?? 4096;
  }

  /**
   * The ID of the last event this transport delivered (the SSE cursor), or
   * undefined when none was received or the cursor was discarded after a gap.
   * Event IDs are opaque: store and send them back, never parse or compare.
   */
  get lastEventId(): string | undefined {
    return this.cursor;
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
    if (this.sessionId !== undefined && this.sessionId !== sessionId) {
      // Event IDs are unique only within a session: another session's cursor
      // would draw a 410 and its seen IDs could swallow this session's events.
      this.cursor = undefined;
      this.seenIds.clear();
      this.pendingGap = false;
    }
    this.sessionId = sessionId;
  }

  /**
   * Connect the SSE stream. Call this after constructing the transport.
   * Separated from the constructor so callers can register listeners first.
   * Resumes from the transport's own cursor unless `lastEventId` is given.
   */
  connectSSE(lastEventId?: string): void {
    if (lastEventId !== undefined) this.cursor = lastEventId || undefined;
    this.openStream(this.cursor);
  }

  /**
   * Reconnect the SSE stream with the current authorization/session state
   * and the recorded cursor. Useful after calling setAuthorization.
   */
  reconnectSSE(lastEventId?: string): void {
    this.connectSSE(lastEventId);
  }

  private streamHeaders(cursor?: string): Record<string, string> {
    const h: Record<string, string> = {};
    if (this.authorization) h["Authorization"] = this.authorization;
    if (cursor) h["Last-Event-ID"] = cursor;
    return h;
  }

  private streamUrl(cursor?: string): string {
    // session_id (required for tenant routing) and the cursor. The cursor goes
    // as last_event_id (Transport Section 4.3.3) and, for servers that predate
    // that name, as lastEventId. Only the query string is touched: a relative
    // URL ("events", "/x", "//host/x") must resolve exactly as it was supplied.
    const hashAt = this.eventsUrl.indexOf("#");
    const hash = hashAt < 0 ? "" : this.eventsUrl.slice(hashAt);
    const noHash = hashAt < 0 ? this.eventsUrl : this.eventsUrl.slice(0, hashAt);
    const qAt = noHash.indexOf("?");
    const base = qAt < 0 ? noHash : noHash.slice(0, qAt);
    const params = new URLSearchParams(qAt < 0 ? "" : noHash.slice(qAt + 1));
    if (this.sessionId) params.set("session_id", this.sessionId);
    // The cursor names are reserved: whatever the supplied URL carried, only the
    // current cursor (none after a 410) goes out, or the recovery request would
    // draw the same 410 again.
    params.delete("last_event_id");
    params.delete("lastEventId");
    if (cursor) {
      params.set("last_event_id", cursor);
      params.set("lastEventId", cursor);
    }
    const query = params.toString();
    return base + (query ? `?${query}` : "") + hash;
  }

  private openStream(cursor: string | undefined): void {
    this.eventSource?.close();
    this.eventSource = null;

    const headers = this.streamHeaders(cursor);
    // Polyfills that can set request headers read `headers` from the init
    // object; a native EventSource ignores it.
    const init = Object.keys(headers).length > 0 ? ({ headers } as EventSourceInit) : undefined;
    const es = new this.EventSourceCtor(this.streamUrl(cursor), init);
    this.eventSource = es;

    es.onopen = () => {
      this.emit("open");
      if (this.pendingGap) {
        this.pendingGap = false;
        this.emit("gap");
      }
    };
    es.onerror = () => {
      if (this.closed || this.eventSource !== es) return;
      // A closed stream with a cursor may be the 410 of a gap; the EventSource
      // API does not expose the status, so ask.
      if (es.readyState === 2 /* CLOSED */ && this.cursor) {
        void this.checkGap(es, this.cursor);
        return;
      }
      this.emit("error", new Error("SSE connection error"));
    };

    // WMP events use the "wmp" event type per the spec.
    es.addEventListener("wmp", (ev) => this.onSseEvent(ev as MessageEvent));
    // Also handle default "message" events for compatibility.
    es.onmessage = (ev) => this.onSseEvent(ev);
  }

  /**
   * Handles one SSE event: an event whose ID was already processed (a replay
   * after a reconnect) is dropped; otherwise it is delivered and then its ID
   * becomes the cursor (Transport Section 4.3.2).
   */
  private onSseEvent(ev: MessageEvent): void {
    const id = typeof ev.lastEventId === "string" && ev.lastEventId !== "" ? ev.lastEventId : undefined;
    if (id !== undefined && this.seenIds.has(id)) return;
    try {
      this.emit("message", decodeMessage(ev.data, { maxSize: 4 * 1024 * 1024 }));
    } catch (err) {
      this.emit("error", err instanceof Error ? err : new Error(String(err)));
    } finally {
      if (id !== undefined) this.recordEventId(id);
    }
  }

  private recordEventId(id: string): void {
    this.cursor = id;
    this.seenIds.add(id);
    if (this.seenIds.size > this.dedupeWindow) {
      // Sets iterate in insertion order: drop the oldest.
      this.seenIds.delete(this.seenIds.values().next().value as string);
    }
  }

  /** Probes the stream URL for a 410 after the EventSource gave up with `cursor`. */
  private async checkGap(failed: EventSource, cursor: string): Promise<void> {
    let status: number | undefined;
    try {
      const abort = new AbortController();
      const resp = await this.fetchFn(this.streamUrl(cursor), {
        headers: { ...this.streamHeaders(cursor), Accept: "text/event-stream" },
        signal: abort.signal,
      });
      status = resp.status;
      abort.abort(); // only the status matters; do not hold the stream open
    } catch {
      status = undefined;
    }
    if (this.closed || this.eventSource !== failed) return;
    if (status === 410) {
      // Discard the cursor (never reconnect with it again) and open a stream
      // with none; "gap" is emitted once it is open, so the resume's re-sent
      // notifications have a connection to arrive on.
      this.cursor = undefined;
      this.pendingGap = true;
      this.openStream(undefined);
      return;
    }
    this.emit("error", new Error("SSE connection error"));
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
