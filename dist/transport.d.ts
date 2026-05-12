/**
 * Transport interface and implementations — mirrors go-wmp/pkg/wmp/transport.go.
 *
 * Two transport implementations:
 *   - WebSocketTransport: bidirectional, persistent connection
 *   - HttpSseTransport: POST for sending + SSE EventSource for receiving
 */
import { type Message } from "./jsonrpc.js";
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
    off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;
}
type Listener = (...args: unknown[]) => void;
declare class Emitter {
    private listeners;
    on(event: string, fn: Listener): void;
    off(event: string, fn: Listener): void;
    protected emit(event: string, ...args: unknown[]): void;
}
export interface WebSocketTransportOptions {
    /** WebSocket subprotocol. Default: "wmp.v1" */
    protocols?: string | string[];
}
/**
 * WebSocket transport — bidirectional, persistent connection.
 * Works in browsers (native WebSocket) and Node.js (e.g., ws package).
 */
export declare class WebSocketTransport extends Emitter implements Transport {
    private ws;
    constructor(url: string, opts?: WebSocketTransportOptions);
    send(msg: Message): Promise<void>;
    close(): void;
    on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;
    off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;
}
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
export declare class HttpSseTransport extends Emitter implements Transport {
    private rpcUrl;
    private eventsUrl;
    private authorization?;
    private sessionId?;
    private eventSource;
    private fetchFn;
    private EventSourceCtor;
    private closed;
    constructor(rpcUrl: string, eventsUrl: string, opts?: HttpSseTransportOptions);
    /**
     * Update the authorization header (e.g., after token refresh).
     * Takes effect on the next POST request.
     */
    setAuthorization(authorization: string): void;
    /**
     * Bind a session ID to this transport. The session ID is sent as:
     * - `Wmp-Session-Id` header on POST requests (per WMP spec §4.5)
     * - `session_id` query parameter on SSE connections
     */
    setSessionId(sessionId: string): void;
    /**
     * Connect the SSE stream. Call this after constructing the transport.
     * Separated from the constructor so callers can register listeners first.
     */
    connectSSE(lastEventId?: string): void;
    send(msg: Message): Promise<void>;
    close(): void;
    on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;
    off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void;
}
export {};
