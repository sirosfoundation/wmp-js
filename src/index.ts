/**
 * @siros/wmp — Wallet Messaging Protocol client library
 */

// Types
export {
  VERSION,
  Method,
  ErrorCode,
  FlowType,
  CloseReason,
  AckStatus,
  CancelReason,
  ResolveType,
} from "./types.js";
export type {
  Metadata,
  IdentityAssertion,
  TrustHint,
  RelayEntry,
  SecurityMode,
  Capabilities,
  AuthObject,
  SessionCreateParams,
  SessionCreateResult,
  SessionResumeParams,
  SessionCloseParams,
  SessionAuthenticateParams,
  SessionAuthenticateResult,
  MessageDeliverParams,
  MessageAckParams,
  MessagePollParams,
  MessagePollResult,
  MessageStatusParams,
  CapabilityUpdateParams,
  CapabilityUpdateResult,
  CapabilityListParams,
  CapabilityListResult,
  FlowStartParams,
  FlowStartResult,
  FlowProgressParams,
  FlowActionParams,
  FlowActionResult,
  FlowCompleteParams,
  FlowErrorParams,
  FlowCancelParams,
  FlowCancelResult,
  ResolveParams,
  ResolveResult,
  MethodName,
} from "./types.js";

// JSON-RPC
export {
  WMPError,
  createRequest,
  createNotification,
  createResponse,
  createErrorResponse,
  decodeMessage,
  decodeBatch,
  isRequest,
  isResponse,
  isNotification,
} from "./jsonrpc.js";
export type { RPCError, Request, Response, Message } from "./jsonrpc.js";

// Transport
export { WebSocketTransport, HttpSseTransport } from "./transport.js";
export type {
  Transport,
  TransportEvents,
  TransportEventName,
  WebSocketTransportOptions,
  HttpSseTransportOptions,
} from "./transport.js";

// Profile system
export { Registry } from "./profile.js";
export type {
  Profile,
  PeerContext,
  FlowHandler,
  MethodHandler,
  ResolveHandler,
} from "./profile.js";

// Peer
export { Peer } from "./peer.js";
export type { Handler, PeerOptions } from "./peer.js";
