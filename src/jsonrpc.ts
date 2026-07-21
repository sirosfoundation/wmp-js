/**
 * JSON-RPC 2.0 message types — mirrors go-wmp/pkg/wmp/jsonrpc.go.
 */

export interface RPCError {
  code: number;
  message: string;
  data?: unknown;
}

export interface Request {
  jsonrpc: "2.0";
  id?: string | number;
  method: string;
  params: unknown;
}

export interface Response {
  jsonrpc: "2.0";
  id: string | number | null;
  result?: unknown;
  error?: RPCError;
}

export type Message = Request | Response;

/** Type guard: is this a JSON-RPC request/notification? */
export function isRequest(msg: Message): msg is Request {
  return "method" in msg && typeof (msg as Request).method === "string";
}

/** Type guard: is this a JSON-RPC response? */
export function isResponse(msg: Message): msg is Response {
  return "result" in msg || "error" in msg;
}

/** Type guard: is this a notification (request with no id)? */
export function isNotification(msg: Request): boolean {
  return msg.id === undefined || msg.id === null;
}

/** Generate a cryptographically random request ID. */
function generateRequestId(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const b64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `req-${b64}`;
}

/** Create a JSON-RPC 2.0 request. */
export function createRequest(method: string, params: unknown): Request {
  return { jsonrpc: "2.0", id: generateRequestId(), method, params };
}

/** Create a JSON-RPC 2.0 notification (no id, no response expected). */
export function createNotification(method: string, params: unknown): Request {
  return { jsonrpc: "2.0", method, params };
}

/** Create a JSON-RPC 2.0 success response. */
export function createResponse(
  id: string | number | null,
  result: unknown,
): Response {
  return { jsonrpc: "2.0", id, result };
}

/** Create a JSON-RPC 2.0 error response. */
export function createErrorResponse(
  id: string | number | null,
  error: RPCError,
): Response {
  return { jsonrpc: "2.0", id, error };
}

export interface DecodeOptions {
  /** Maximum payload length in characters. Default: 4 MB. */
  maxSize?: number;
  /** Maximum object/array nesting depth. Default: 32. */
  maxDepth?: number;
}

const DEFAULT_MAX_SIZE = 4 * 1024 * 1024;
const DEFAULT_MAX_DEPTH = 32;

function checkDepth(value: unknown, depth: number, maxDepth: number): void {
  if (depth > maxDepth) {
    throw new Error("JSON-RPC message exceeds maximum nesting depth");
  }
  if (Array.isArray(value)) {
    for (const item of value) checkDepth(item, depth + 1, maxDepth);
  } else if (value !== null && typeof value === "object") {
    for (const key in value) {
      if (Object.prototype.hasOwnProperty.call(value, key)) {
        checkDepth((value as Record<string, unknown>)[key], depth + 1, maxDepth);
      }
    }
  }
}

/** Parse a raw JSON string into a Message. Throws on invalid JSON-RPC. */
export function decodeMessage(data: string, opts?: DecodeOptions): Message {
  const maxSize = opts?.maxSize ?? DEFAULT_MAX_SIZE;
  const maxDepth = opts?.maxDepth ?? DEFAULT_MAX_DEPTH;

  if (data.length > maxSize) {
    throw new Error("JSON-RPC message exceeds maximum size");
  }

  let obj: unknown;
  try {
    obj = JSON.parse(data, (_key, value) => {
      if (value !== null && typeof value === "object") {
        checkDepth(value, 1, maxDepth);
      }
      return value;
    });
  } catch (err) {
    if (err instanceof Error && err.message.includes("depth")) {
      throw err;
    }
    throw new Error("Invalid JSON-RPC payload");
  }

  if (obj === null || typeof obj !== "object" || (obj as Message).jsonrpc !== "2.0") {
    throw new Error("Invalid JSON-RPC version");
  }
  return obj as Message;
}

/** Parse raw JSON that may be a batch (array) or single message. */
export function decodeBatch(data: string, opts?: DecodeOptions): Message[] {
  const maxSize = opts?.maxSize ?? DEFAULT_MAX_SIZE;
  const maxDepth = opts?.maxDepth ?? DEFAULT_MAX_DEPTH;

  if (data.length > maxSize) {
    throw new Error("JSON-RPC message exceeds maximum size");
  }

  let obj: unknown;
  try {
    obj = JSON.parse(data, (_key, value) => {
      if (value !== null && typeof value === "object") {
        checkDepth(value, 1, maxDepth);
      }
      return value;
    });
  } catch (err) {
    if (err instanceof Error && err.message.includes("depth")) {
      throw err;
    }
    throw new Error("Invalid JSON-RPC payload");
  }

  if (Array.isArray(obj)) {
    return obj.map((item) => {
      if (item.jsonrpc !== "2.0") {
        throw new Error("Invalid JSON-RPC version in batch");
      }
      return item as Message;
    });
  }
  if (obj === null || typeof obj !== "object" || (obj as Message).jsonrpc !== "2.0") {
    throw new Error("Invalid JSON-RPC version");
  }
  return [obj as Message];
}

/** WMP-specific RPC error class. */
export class WMPError extends Error {
  readonly code: number;
  readonly data?: unknown;

  constructor(code: number, message: string, data?: unknown) {
    super(`wmp: rpc error ${code}: ${message}`);
    this.name = "WMPError";
    this.code = code;
    this.data = data;
  }

  toRPCError(): RPCError {
    return { code: this.code, message: this.message, data: this.data };
  }
}

/** @deprecated Request IDs are now random; this function is a no-op for compatibility. */
export function resetRequestIdCounter(): void {
  // no-op: IDs are cryptographically random.
}
