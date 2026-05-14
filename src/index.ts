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
  ServiceClass,
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
  SessionResumeResult,
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
  RelayRegisterParams,
  RelayRegisterResult,
  RelayCap,
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

// MLS
export {
  MLSMethod,
  CipherSuiteX25519AES128GCM,
  CipherSuiteP256AES128GCM,
  CredentialType,
  MLSProfile,
  mlsMethods,
  NoopMLSHandler,
  NoopMLSProvider,
} from "./mls.js";
export type {
  MLSMethodName,
  GroupCreateParams,
  GroupCreateResult,
  GroupJoinParams,
  GroupJoinResult,
  GroupAddParams,
  GroupAddResult,
  GroupRemoveParams,
  GroupRemoveResult,
  GroupUpdateParams,
  MessageFetchParams,
  MessageFetchResult,
  KeyPackage,
  KeyPackagesResponse,
  EncryptedEnvelope,
  MLSHandler,
  MLSProvider,
} from "./mls.js";

// OpenID4x
export {
  CredentialFormat,
  allFormats,
  isValidFormat,
  GrantType,
  ResponseMode,
  ProofType,
  OID4FlowType,
  VCIStep,
  VPStep,
  OID4Action,
  OpenID4xProfile,
} from "./openid4x.js";
export type {
  CredentialFormatType,
  OID4VCICapability,
  OID4VPCapability,
  CredentialDisplay,
  CredentialConfigurationSupported,
  CredentialResult,
  VPTokenResult,
  SignSubFlowParams,
  SelectionAction,
  ConsentAction,
  CredentialSelection,
  FlowStartHandler,
  ActionHandler,
  OpenID4xConfig,
} from "./openid4x.js";

// Relay
export { Relay } from "./relay.js";
export type { RelayConfig, QueuedMessage } from "./relay.js";
