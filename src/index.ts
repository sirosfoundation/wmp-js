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
  ConsignmentMode,
  AssuranceLevel,
  CancelReason,
  ResolveType,
  ServiceClass,
  AuthType,
} from "./types.js";
export type {
  Metadata,
  IdentityAssertion,
  TrustHint,
  RelayEntry,
  SenderDelegate,
  DelegateAuthorization,
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
export { TsMlsProvider } from "./mls-provider.js";
export type { TsMlsProviderOptions } from "./mls-provider.js";
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

// Version negotiation and errors
export { SUPPORTED_VERSIONS, parseVersion, negotiateVersion, versionRejection } from "./version.js";
export { unsupportedError } from "./errors.js";

// Completion-result rules (OpenID4x profile 3.1.4, 3.3)
export {
  validateCompletionResult,
  validateMatchResult,
  dcqlQueryIds,
  splitReplaySecrets,
  redactedMembers,
  CompletionResultError,
  DEFAULT_SECRET_MEMBERS,
  REPLAY_SECRET_MEMBERS,
  MAX_ENCRYPTED_CREDENTIAL_COUNT,
  MAX_RESPONSE_JWE_LEN,
} from "./completion.js";
export type { ReplaySplit } from "./completion.js";

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
  buildVCIFlowStart,
  withAttestation,
  transactionDataHashesAlgs,
  SubFlowRejectedError,
} from "./openid4x.js";
export type {
  CredentialFormatType,
  OID4VCICapability,
  OID4VPCapability,
  CredentialDisplay,
  CredentialConfigurationSupported,
  CredentialResult,
  CredentialEvent,
  CredentialNotificationParams,
  VPTokenResult,
  ClientAttestation,
  ClientAttestationProvider,
  OID4VCIFlowParams,
  OID4VPFlowParams,
  SignSubFlowParams,
  SelectionAction,
  ConsentAction,
  CredentialSelection,
  CredentialToInclude,
  CredentialResponseEncryption,
  TransactionData,
  FlowStartHandler,
  ActionHandler,
  OpenID4xConfig,
} from "./openid4x.js";

// Sign sub-flow responder, transaction_data, match (profile 3.1.5, 3.2.5, 3.2.6, 3.3)
export {
  CAPABILITY_TRANSACTION_DATA,
  TRANSACTION_DATA_VERSION_1,
  TRANSACTION_DATA_HASH_ALGS,
  SIGN_ACTIONS,
  MAX_PROOF_COUNT,
  SignFlow,
  offersTransactionData,
  transactionDataUnsupportedData,
  transactionDataUnsupportedError,
  transactionDataHash,
  decodeTransactionData,
  checkTransactionDataEntry,
  parseSignSubFlowParams,
  parseMatchStartParams,
  dcqlQueryIds,
  completeSubFlow,
  failSubFlow,
  rejectSubFlow,
  unsupportedTransactionData,
} from "./signflow.js";
export type { TransactionDataCapability, MatchStartParams, MatchResult, FlowNotifier } from "./signflow.js";

// select_credentials consent action (profile 3.2.3.1)
export {
  ActionParamsError,
  validateSelectCredentialsParams,
  buildSelectCredentials,
  newSelectionHandle,
  isSelectionHandle,
  isQueryId,
} from "./consent.js";
export type { SelectCredentialsContext } from "./consent.js";

// Evidence (ERDS)
export { EvidenceEvent, EventReasonCode } from "./evidence.js";
export type {
  EvidenceEventType,
  EvidenceEventReason,
  EvidenceIssuer,
  ExternalSystem,
  ExternalErds,
  EvidenceNotifyParams,
} from "./evidence.js";

// Relay
export { Relay } from "./relay.js";
export type { RelayConfig, QueuedMessage } from "./relay.js";

// Session store (server-side)
export {
  MemorySessionStore,
  SessionStoreError,
  isSessionExpired,
  sessionOwnedBy,
  tokensEqual,
} from "./session-store.js";
export type {
  Session,
  SessionStore,
  SessionStoreErrorCode,
  TokenRotator,
  SessionCreator,
  SessionUpdater,
  ExpiredSessionLister,
} from "./session-store.js";

// Discovery
export { extractDomain, discoverEndpoint } from "./discovery.js";
export type { WellKnownConfig } from "./discovery.js";
export type { ErdsMetadata, RecipientMetadata } from "./discovery.js";

// Invitation
export {
  InvitationPurpose,
  createInvitation,
  invitationSigningPayload,
  invitationToURI,
  invitationToHTTPSURI,
  parseInvitationURI,
  parseInvitationJSON,
  isInvitationExpired,
  generateNonce,
  MemoryInvitationStore,
  validateInvitationNonce,
} from "./invitation.js";
export type {
  Invitation,
  CreateInvitationOptions,
  InvitationStore,
} from "./invitation.js";
