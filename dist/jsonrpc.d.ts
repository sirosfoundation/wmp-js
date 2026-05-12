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
export declare function isRequest(msg: Message): msg is Request;
/** Type guard: is this a JSON-RPC response? */
export declare function isResponse(msg: Message): msg is Response;
/** Type guard: is this a notification (request with no id)? */
export declare function isNotification(msg: Request): boolean;
/** Create a JSON-RPC 2.0 request. */
export declare function createRequest(method: string, params: unknown): Request;
/** Create a JSON-RPC 2.0 notification (no id, no response expected). */
export declare function createNotification(method: string, params: unknown): Request;
/** Create a JSON-RPC 2.0 success response. */
export declare function createResponse(id: string | number | null, result: unknown): Response;
/** Create a JSON-RPC 2.0 error response. */
export declare function createErrorResponse(id: string | number | null, error: RPCError): Response;
/** Parse a raw JSON string into a Message. Throws on invalid JSON-RPC. */
export declare function decodeMessage(data: string): Message;
/** Parse raw JSON that may be a batch (array) or single message. */
export declare function decodeBatch(data: string): Message[];
/** WMP-specific RPC error class. */
export declare class WMPError extends Error {
    readonly code: number;
    readonly data?: unknown;
    constructor(code: number, message: string, data?: unknown);
    toRPCError(): RPCError;
}
/** Reset the request ID counter (for testing). */
export declare function resetRequestIdCounter(): void;
