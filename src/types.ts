/**
 * WMP protocol types — mirrors go-wmp/pkg/wmp/types.go and methods.go.
 */

export const VERSION = "0.1";

// ---------------------------------------------------------------------------
// WMP metadata envelope (present in every message's params.wmp / result.wmp)
// ---------------------------------------------------------------------------

export interface Metadata {
  version: string;
  session_id?: string;
  sender?: string;
  timestamp?: string;
  timestamp_token?: string;
  expires_at?: string;
  encrypted?: boolean;
  epoch?: number;
  signature?: string;
  identity_assertions?: IdentityAssertion[];
  relay_chain?: RelayEntry[];
  trace_id?: string;
}

export interface IdentityAssertion {
  type: string;
  format?: string;
  vp_token?: string;
  audience?: string;
  nonce?: string;
  disclosed_claims?: string[];
  x5c?: string[];
  trust_hints?: TrustHint[];
}

export interface TrustHint {
  framework: string;
  lote_url?: string;
  issuer_service_id?: string;
  trust_anchor?: string;
  entity_statement?: string;
  root_ca?: string;
  uri?: string;
  validation_endpoint?: string;
}

export interface RelayEntry {
  relay: string;
  relay_id: string;
  timestamp: string;
  timestamp_token?: string;
  signature?: string;
  service_class?: string;
}

export interface SecurityMode {
  mode: string;
  min_tls_version?: string;
  cipher_suites?: number[];
  cipher_suite?: number;
  mls_group_info?: string;
  encrypted_capabilities?: string[];
}

export type Capabilities = Record<string, unknown>;

// ---------------------------------------------------------------------------
// Method constants
// ---------------------------------------------------------------------------

export const Method = {
  SessionCreate: "wmp.session.create",
  SessionResume: "wmp.session.resume",
  SessionClose: "wmp.session.close",
  SessionAuthenticate: "wmp.session.authenticate",
  MessageDeliver: "wmp.message.deliver",
  MessageAck: "wmp.message.ack",
  MessagePoll: "wmp.message.poll",
  MessageStatus: "wmp.message.status",
  CapabilityUpdate: "wmp.capability.update",
  CapabilityList: "wmp.capability.list",
  FlowStart: "wmp.flow.start",
  FlowProgress: "wmp.flow.progress",
  FlowAction: "wmp.flow.action",
  FlowComplete: "wmp.flow.complete",
  FlowError: "wmp.flow.error",
  FlowCancel: "wmp.flow.cancel",
  CredentialNotification: "wmp.credential.notification",
  Resolve: "wmp.resolve",
  RelayRegister: "wmp.relay.register",
} as const;

export type MethodName = (typeof Method)[keyof typeof Method];

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

export const ErrorCode = {
  ParseError: -32700,
  InvalidRequest: -32600,
  MethodNotFound: -32601,
  InvalidParams: -32602,
  InternalError: -32603,
  SessionNotFound: -31000,
  SessionExpired: -31001,
  NotAuthorized: -31002,
  EncryptionRequired: -31003,
  MLSError: -31004,
  CapabilityNotSupported: -31005,
  FlowError: -31006,
  RateLimited: -31007,
  ParticipantNotFound: -31008,
  EvidenceRequired: -31009,
  SignatureInvalid: -31010,
  TimestampInvalid: -31011,
  IdentityAssertionInvalid: -31012,
  VersionNotSupported: -31013,
  QueueFull: -31014,
} as const;

// ---------------------------------------------------------------------------
// Session methods
// ---------------------------------------------------------------------------

export interface AuthObject {
  type: string;
  token?: string;
  signature?: string;
  x5c?: string[];
  [key: string]: unknown;
}

/** Authentication type constants. */
export const AuthType = {
  Bearer: "bearer",
  DPoP: "dpop",
  MTLS: "mtls",
  SignedChallenge: "signed_challenge",
  X5C: "x5c",
  /** @deprecated Use SignedChallenge instead. */
  DIDAuth: "did_auth",
} as const;

export interface SessionCreateParams {
  wmp: Metadata;
  participants?: string[];
  capabilities_offered?: Capabilities;
  security: SecurityMode;
  ttl?: number;
  auth?: AuthObject;
  invitation_nonce?: string;
}

export interface SessionCreateResult {
  wmp: Metadata;
  capabilities?: Capabilities;
  security: SecurityMode;
  challenge?: string;
  resumption_token?: string;
}

export interface SessionResumeParams {
  wmp: Metadata;
  session_id: string;
  resumption_token: string;
  last_received_id?: string;
}

export interface SessionResumeResult {
  wmp: Metadata;
  resumed: boolean;
  resumption_token?: string;
  missed_messages: number;
  capabilities?: Capabilities;
  security: SecurityMode;
}

export interface SessionCloseParams {
  wmp: Metadata;
  reason: string;
}

export interface SessionAuthenticateParams {
  wmp: Metadata;
  type: string;
  token?: string;
  response?: string;
  [key: string]: unknown;
}

export interface SessionAuthenticateResult {
  wmp: Metadata;
  authenticated: boolean;
}

// Close reason constants.
export const CloseReason = {
  Complete: "complete",
  Timeout: "timeout",
  Error: "error",
  UserCancelled: "user_cancelled",
} as const;

// ---------------------------------------------------------------------------
// Message methods
// ---------------------------------------------------------------------------

export interface MessageDeliverParams {
  wmp: Metadata;
  to?: string[];
  content_type?: string;
  body?: unknown;
  ciphertext?: string;
}

export interface MessageAckParams {
  wmp: Metadata;
  message_ids: string[];
  status: string;
}

export interface MessagePollParams {
  wmp: Metadata;
  since?: string;
  limit?: number;
}

export interface MessagePollResult {
  wmp: Metadata;
  messages: unknown[];
}

export interface MessageStatusParams {
  wmp: Metadata;
  message_id: string;
  status: string;
  reason?: string;
}

export const AckStatus = {
  Received: "received",
  Read: "read",
  Processed: "processed",
  Failed: "failed",
} as const;

// ---------------------------------------------------------------------------
// Capability methods
// ---------------------------------------------------------------------------

export interface CapabilityUpdateParams {
  wmp: Metadata;
  add?: Capabilities;
  remove?: string[];
  security?: SecurityMode;
}

export interface CapabilityUpdateResult {
  wmp: Metadata;
  capabilities: Capabilities;
  security: SecurityMode;
}

export interface CapabilityListParams {
  wmp: Metadata;
}

export interface CapabilityListResult {
  wmp: Metadata;
  capabilities: Capabilities;
  security: SecurityMode;
}

// ---------------------------------------------------------------------------
// Flow methods
// ---------------------------------------------------------------------------

export interface FlowStartParams {
  wmp: Metadata;
  flow_type: string;
  flow_id: string;
  params?: unknown;
  timeout?: number;
}

export interface FlowStartResult {
  wmp: Metadata;
  flow_id: string;
  flow_type: string;
}

export interface FlowProgressParams {
  wmp: Metadata;
  flow_id: string;
  step: string;
  payload?: unknown;
}

export interface FlowActionParams {
  wmp: Metadata;
  flow_id: string;
  action: string;
  params?: unknown;
}

export interface FlowActionResult {
  wmp: Metadata;
  flow_id: string;
  action: string;
  status: string;
}

export interface FlowCompleteParams {
  wmp: Metadata;
  flow_id: string;
  result?: unknown;
}

export interface FlowErrorParams {
  wmp: Metadata;
  flow_id: string;
  code: number;
  message: string;
  data?: unknown;
}

export interface FlowCancelParams {
  wmp: Metadata;
  flow_id: string;
  reason?: string;
}

export interface FlowCancelResult {
  wmp: Metadata;
  flow_id: string;
  status: string;
}

export const FlowType = {
  Approval: "approval",
  Sign: "sign",
  Message: "message",
} as const;

export const CancelReason = {
  UserCancelled: "user_cancelled",
  Superseded: "superseded",
  NoLongerNeeded: "no_longer_needed",
} as const;

// ---------------------------------------------------------------------------
// Resolve methods
// ---------------------------------------------------------------------------

export interface ResolveParams {
  wmp: Metadata;
  type: string;
  uri: string;
  options?: unknown;
}

export interface ResolveResult {
  wmp: Metadata;
  type: string;
  uri: string;
  metadata: unknown;
  trust_info?: unknown;
}

export const ResolveType = {
  VCTM: "vctm",
  IssuerMetadata: "issuer_metadata",
  Trust: "trust",
  Endpoint: "endpoint",
  OpenIDFederation: "openid_federation",
} as const;

// ---------------------------------------------------------------------------
// Relay methods
// ---------------------------------------------------------------------------

export interface RelayRegisterParams {
  wmp: Metadata;
  auth?: AuthObject;
}

export interface RelayRegisterResult {
  wmp: Metadata;
  registered: boolean;
  ttl?: number;
}

export interface RelayCap {
  destinations?: string[];
}

export const ServiceClass = {
  BestEffort: "best_effort",
  Standard: "standard",
  Registered: "registered",
  Certified: "certified",
} as const;
