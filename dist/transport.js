/**
 * Transport interface and implementations — mirrors go-wmp/pkg/wmp/transport.go.
 *
 * Two transport implementations:
 *   - WebSocketTransport: bidirectional, persistent connection
 *   - HttpSseTransport: POST for sending + SSE EventSource for receiving
 */
import { decodeMessage } from "./jsonrpc.js";
class Emitter {
    listeners = new Map();
    on(event, fn) {
        let set = this.listeners.get(event);
        if (!set) {
            set = new Set();
            this.listeners.set(event, set);
        }
        set.add(fn);
    }
    off(event, fn) {
        this.listeners.get(event)?.delete(fn);
    }
    emit(event, ...args) {
        this.listeners.get(event)?.forEach((fn) => fn(...args));
    }
}
/**
 * WebSocket transport — bidirectional, persistent connection.
 * Works in browsers (native WebSocket) and Node.js (e.g., ws package).
 */
export class WebSocketTransport extends Emitter {
    ws;
    constructor(url, opts) {
        super();
        const protocols = opts?.protocols ?? "wmp.v1";
        this.ws = new WebSocket(url, protocols);
        this.ws.onopen = () => this.emit("open");
        this.ws.onclose = () => this.emit("close");
        this.ws.onerror = (ev) => {
            const err = ev instanceof ErrorEvent ? new Error(ev.message) : new Error("WebSocket error");
            this.emit("error", err);
        };
        this.ws.onmessage = (ev) => {
            try {
                const msg = decodeMessage(String(ev.data));
                this.emit("message", msg);
            }
            catch (err) {
                this.emit("error", err instanceof Error ? err : new Error(String(err)));
            }
        };
    }
    async send(msg) {
        if (this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocket is not open");
        }
        this.ws.send(JSON.stringify(msg));
    }
    close() {
        this.ws.close();
    }
    on(event, listener) {
        super.on(event, listener);
    }
    off(event, listener) {
        super.off(event, listener);
    }
}
/**
 * HTTP+SSE transport — POST for outgoing, EventSource for incoming.
 *
 * POST endpoint receives JSON-RPC requests.
 * SSE endpoint streams server-initiated JSON-RPC notifications/responses.
 */
export class HttpSseTransport extends Emitter {
    rpcUrl;
    eventsUrl;
    authorization;
    sessionId;
    eventSource = null;
    fetchFn;
    EventSourceCtor;
    closed = false;
    constructor(rpcUrl, eventsUrl, opts) {
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
    setAuthorization(authorization) {
        this.authorization = authorization;
    }
    /**
     * Bind a session ID to this transport. The session ID is sent as:
     * - `Wmp-Session-Id` header on POST requests (per WMP spec §4.5)
     * - `session_id` query parameter on SSE connections
     */
    setSessionId(sessionId) {
        this.sessionId = sessionId;
    }
    /**
     * Connect the SSE stream. Call this after constructing the transport.
     * Separated from the constructor so callers can register listeners first.
     */
    connectSSE(lastEventId) {
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
                const msg = decodeMessage(ev.data);
                this.emit("message", msg);
            }
            catch (err) {
                this.emit("error", err instanceof Error ? err : new Error(String(err)));
            }
        });
        // Also handle default "message" events for compatibility.
        this.eventSource.onmessage = (ev) => {
            try {
                const msg = decodeMessage(ev.data);
                this.emit("message", msg);
            }
            catch (err) {
                this.emit("error", err instanceof Error ? err : new Error(String(err)));
            }
        };
    }
    async send(msg) {
        if (this.closed) {
            throw new Error("Transport is closed");
        }
        const headers = {
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
                }
                catch {
                    // Non-JSON-RPC body — ignore.
                }
            }
        }
    }
    close() {
        this.closed = true;
        this.eventSource?.close();
        this.eventSource = null;
        this.emit("close");
    }
    on(event, listener) {
        super.on(event, listener);
    }
    off(event, listener) {
        super.off(event, listener);
    }
}
