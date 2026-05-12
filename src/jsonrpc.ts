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

let nextId = 1;

/** Create a JSON-RPC 2.0 request. */
export function createRequest(method: string, params: unknown): Request {
  return { jsonrpc: "2.0", id: `req-${nextId++}`, method, params };
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

/** Parse a raw JSON string into a Message. Throws on invalid JSON-RPC. */
export function decodeMessage(data: string): Message {
  const obj = JSON.parse(data);
  if (obj.jsonrpc !== "2.0") {
    throw new Error("Invalid JSON-RPC version");
  }
  return obj as Message;
}

/** Parse raw JSON that may be a batch (array) or single message. */
export function decodeBatch(data: string): Message[] {
  const obj = JSON.parse(data);
  if (Array.isArray(obj)) {
    return obj.map((item) => {
      if (item.jsonrpc !== "2.0") {
        throw new Error("Invalid JSON-RPC version in batch");
      }
      return item as Message;
    });
  }
  if (obj.jsonrpc !== "2.0") {
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

/** Reset the request ID counter (for testing). */
export function resetRequestIdCounter(): void {
  nextId = 1;
}
