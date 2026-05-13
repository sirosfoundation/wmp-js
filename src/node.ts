/**
 * Node.js entry point — re-exports everything from the main entry
 * plus Node.js-only modules (native transports, schema validation).
 *
 * Usage:
 *   import { createValidator, StdioTransport } from '@sirosfoundation/wmp-js/node';
 */

export * from "./index.js";

// Native transports (Node.js only — stdio NDJSON, Unix sockets)
export { StdioTransport, UnixSocketTransport } from "./native.js";
export type { StdioTransportOptions } from "./native.js";

// Schema validation (Node.js only — requires fs)
export { createValidator } from "./schema.js";
export type { Validator, ValidationError } from "./schema.js";
