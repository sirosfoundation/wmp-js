/**
 * JSON-RPC 2.0 message types — mirrors go-wmp/pkg/wmp/jsonrpc.go.
 */
/** Type guard: is this a JSON-RPC request/notification? */
export function isRequest(msg) {
    return "method" in msg && typeof msg.method === "string";
}
/** Type guard: is this a JSON-RPC response? */
export function isResponse(msg) {
    return "result" in msg || "error" in msg;
}
/** Type guard: is this a notification (request with no id)? */
export function isNotification(msg) {
    return msg.id === undefined || msg.id === null;
}
let nextId = 1;
/** Create a JSON-RPC 2.0 request. */
export function createRequest(method, params) {
    return { jsonrpc: "2.0", id: `req-${nextId++}`, method, params };
}
/** Create a JSON-RPC 2.0 notification (no id, no response expected). */
export function createNotification(method, params) {
    return { jsonrpc: "2.0", method, params };
}
/** Create a JSON-RPC 2.0 success response. */
export function createResponse(id, result) {
    return { jsonrpc: "2.0", id, result };
}
/** Create a JSON-RPC 2.0 error response. */
export function createErrorResponse(id, error) {
    return { jsonrpc: "2.0", id, error };
}
/** Parse a raw JSON string into a Message. Throws on invalid JSON-RPC. */
export function decodeMessage(data) {
    const obj = JSON.parse(data);
    if (obj.jsonrpc !== "2.0") {
        throw new Error("Invalid JSON-RPC version");
    }
    return obj;
}
/** Parse raw JSON that may be a batch (array) or single message. */
export function decodeBatch(data) {
    const obj = JSON.parse(data);
    if (Array.isArray(obj)) {
        return obj.map((item) => {
            if (item.jsonrpc !== "2.0") {
                throw new Error("Invalid JSON-RPC version in batch");
            }
            return item;
        });
    }
    if (obj.jsonrpc !== "2.0") {
        throw new Error("Invalid JSON-RPC version");
    }
    return [obj];
}
/** WMP-specific RPC error class. */
export class WMPError extends Error {
    code;
    data;
    constructor(code, message, data) {
        super(`wmp: rpc error ${code}: ${message}`);
        this.name = "WMPError";
        this.code = code;
        this.data = data;
    }
    toRPCError() {
        return { code: this.code, message: this.message, data: this.data };
    }
}
/** Reset the request ID counter (for testing). */
export function resetRequestIdCounter() {
    nextId = 1;
}
