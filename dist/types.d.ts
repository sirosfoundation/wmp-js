/**
 * WMP protocol types — mirrors go-wmp/pkg/wmp/types.go and methods.go.
 */
export declare const VERSION = "0.1";
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
export declare const Method: {
    readonly SessionCreate: "wmp.session.create";
    readonly SessionResume: "wmp.session.resume";
    readonly SessionClose: "wmp.session.close";
    readonly SessionAuthenticate: "wmp.session.authenticate";
    readonly MessageDeliver: "wmp.message.deliver";
    readonly MessageAck: "wmp.message.ack";
    readonly MessagePoll: "wmp.message.poll";
    readonly MessageStatus: "wmp.message.status";
    readonly CapabilityUpdate: "wmp.capability.update";
    readonly CapabilityList: "wmp.capability.list";
    readonly FlowStart: "wmp.flow.start";
    readonly FlowProgress: "wmp.flow.progress";
    readonly FlowAction: "wmp.flow.action";
    readonly FlowComplete: "wmp.flow.complete";
    readonly FlowError: "wmp.flow.error";
    readonly FlowCancel: "wmp.flow.cancel";
    readonly Resolve: "wmp.resolve";
};
export type MethodName = (typeof Method)[keyof typeof Method];
export declare const ErrorCode: {
    readonly ParseError: -32700;
    readonly InvalidRequest: -32600;
    readonly MethodNotFound: -32601;
    readonly InvalidParams: -32602;
    readonly InternalError: -32603;
    readonly SessionNotFound: -31000;
    readonly SessionExpired: -31001;
    readonly NotAuthorized: -31002;
    readonly EncryptionRequired: -31003;
    readonly MLSError: -31004;
    readonly CapabilityNotSupported: -31005;
    readonly FlowError: -31006;
    readonly RateLimited: -31007;
    readonly ParticipantNotFound: -31008;
    readonly EvidenceRequired: -31009;
    readonly SignatureInvalid: -31010;
    readonly TimestampInvalid: -31011;
    readonly IdentityAssertionInvalid: -31012;
    readonly VersionNotSupported: -31013;
    readonly QueueFull: -31014;
};
export interface AuthObject {
    type: string;
    token?: string;
    [key: string]: unknown;
}
export interface SessionCreateParams {
    wmp: Metadata;
    participants?: string[];
    capabilities_offered?: Capabilities;
    security: SecurityMode;
    ttl?: number;
    auth?: AuthObject;
}
export interface SessionCreateResult {
    wmp: Metadata;
    capabilities?: Capabilities;
    security: SecurityMode;
    challenge?: string;
}
export interface SessionResumeParams {
    wmp: Metadata;
    session_id: string;
    last_message_id?: string;
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
export declare const CloseReason: {
    readonly Complete: "complete";
    readonly Timeout: "timeout";
    readonly Error: "error";
    readonly UserCancelled: "user_cancelled";
};
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
export declare const AckStatus: {
    readonly Received: "received";
    readonly Read: "read";
    readonly Processed: "processed";
    readonly Failed: "failed";
};
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
export declare const FlowType: {
    readonly Approval: "approval";
    readonly Sign: "sign";
    readonly Message: "message";
};
export declare const CancelReason: {
    readonly UserCancelled: "user_cancelled";
    readonly Superseded: "superseded";
    readonly NoLongerNeeded: "no_longer_needed";
};
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
export declare const ResolveType: {
    readonly VCTM: "vctm";
    readonly IssuerMetadata: "issuer_metadata";
    readonly Trust: "trust";
    readonly Endpoint: "endpoint";
    readonly OpenIDFederation: "openid_federation";
};
