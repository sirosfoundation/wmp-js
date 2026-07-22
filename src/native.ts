/**
 * Native messaging transports — WMP over stdio (NDJSON) and Unix sockets.
 *
 * Per wmp-transport.md §5, native messaging uses newline-delimited JSON
 * over stdin/stdout (for browser extension native messaging and CLI agents)
 * or Unix domain sockets (for local IPC).
 *
 * These transports are Node.js–only (they require `stream.Readable`/`Writable`
 * or `net.Socket`).
 */

import type { Readable, Writable } from "node:stream";
import type { Socket } from "node:net";
import { type Message, decodeMessage } from "./jsonrpc.js";
import type { Transport, TransportEventName, TransportEvents } from "./transport.js";

// ---------------------------------------------------------------------------
// Shared helpers
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

/** Accumulates incoming text, splits on newlines, and decodes JSON-RPC messages. */
class LineBuffer {
  private buffer = "";
  private closed = false;

  constructor(
    private maxLineLength: number,
    private onMessage: (msg: Message) => void,
    private onError: (err: Error) => void,
    private onClose: () => void,
  ) {}

  append(chunk: string): void {
    if (this.closed) return;
    this.buffer += chunk;

    if (this.buffer.length > this.maxLineLength) {
      this.onError(new Error("Native transport line exceeds maximum length"));
      this.close();
      return;
    }

    const lines = this.buffer.split("\n");
    // Last element is incomplete (may be empty string if chunk ended with \n)
    this.buffer = lines.pop()!;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const msg = decodeMessage(trimmed);
        this.onMessage(msg);
      } catch (err) {
        this.onError(err instanceof Error ? err : new Error(String(err)));
      }
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.onClose();
  }
}

// ---------------------------------------------------------------------------
// Stdio transport (NDJSON over stdin/stdout)
// ---------------------------------------------------------------------------

const DEFAULT_MAX_LINE_LENGTH = 1024 * 1024; // 1 MB

export interface StdioTransportOptions {
  /** Readable stream for incoming messages. Default: process.stdin */
  input?: Readable;
  /** Writable stream for outgoing messages. Default: process.stdout */
  output?: Writable;
  /** Maximum line length in characters before the transport is closed. Default: 1 MB. */
  maxLineLength?: number;
}

/**
 * StdioTransport — newline-delimited JSON over stdin/stdout.
 *
 * Suitable for:
 * - Browser extension native messaging hosts
 * - CLI agent communication (MCP-style)
 * - Subprocess WMP peers
 */
export class StdioTransport extends Emitter implements Transport {
  private input: Readable;
  private output: Writable;
  private closed = false;
  private lineBuffer: LineBuffer;

  constructor(opts?: StdioTransportOptions) {
    super();
    this.input = opts?.input ?? process.stdin;
    this.output = opts?.output ?? process.stdout;
    const maxLineLength = opts?.maxLineLength ?? DEFAULT_MAX_LINE_LENGTH;

    this.lineBuffer = new LineBuffer(
      maxLineLength,
      (msg) => this.emit("message", msg),
      (err) => this.emit("error", err),
      () => this.onClose(),
    );

    this.input.setEncoding("utf8");
    this.input.on("data", (chunk: string) => this.lineBuffer.append(chunk));
    this.input.on("end", () => this.lineBuffer.close());
    this.input.on("error", (err: Error) => this.emit("error", err));

    // Emit open on next tick (stream is already connected)
    queueMicrotask(() => this.emit("open"));
  }

  private onClose(): void {
    if (this.closed) return;
    this.closed = true;
    this.emit("close");
  }

  async send(msg: Message): Promise<void> {
    if (this.closed) {
      throw new Error("Transport is closed");
    }
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(msg) + "\n";
      this.output.write(data, "utf8", (err: Error | null | undefined) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    // Don't destroy process.stdin/stdout — just mark closed
    this.emit("close");
  }

  on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    super.on(event, listener as Listener);
  }

  off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    super.off(event, listener as Listener);
  }
}

// ---------------------------------------------------------------------------
// Unix socket transport
// ---------------------------------------------------------------------------

/**
 * UnixSocketTransport — NDJSON over a Unix domain socket.
 *
 * Suitable for local IPC between wallet CLI and agent processes.
 *
 * Usage:
 *   import { connect } from "node:net";
 *   const sock = connect("/tmp/wmp.sock");
 *   const transport = new UnixSocketTransport(sock);
 */
export interface UnixSocketTransportOptions {
  /** Maximum line length in characters before the transport is closed. Default: 1 MB. */
  maxLineLength?: number;
}

export class UnixSocketTransport extends Emitter implements Transport {
  private socket: Socket;
  private closed = false;
  private lineBuffer: LineBuffer;

  constructor(socket: Socket, opts?: UnixSocketTransportOptions) {
    super();
    this.socket = socket;
    const maxLineLength = opts?.maxLineLength ?? DEFAULT_MAX_LINE_LENGTH;

    this.lineBuffer = new LineBuffer(
      maxLineLength,
      (msg) => this.emit("message", msg),
      (err) => this.emit("error", err),
      () => this.onClose(),
    );

    this.socket.setEncoding("utf8");
    this.socket.on("connect", () => this.emit("open"));
    this.socket.on("data", (chunk: string) => this.lineBuffer.append(chunk));
    this.socket.on("end", () => this.lineBuffer.close());
    this.socket.on("close", () => this.lineBuffer.close());
    this.socket.on("error", (err: Error) => this.emit("error", err));

    // If already connected, emit open
    if (!this.socket.connecting) {
      queueMicrotask(() => this.emit("open"));
    }
  }

  private onClose(): void {
    if (this.closed) return;
    this.closed = true;
    this.emit("close");
  }

  async send(msg: Message): Promise<void> {
    if (this.closed) {
      throw new Error("Transport is closed");
    }
    return new Promise((resolve, reject) => {
      const data = JSON.stringify(msg) + "\n";
      this.socket.write(data, "utf8", (err: Error | null | undefined) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.socket.end();
  }

  on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    super.on(event, listener as Listener);
  }

  off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    super.off(event, listener as Listener);
  }
}
