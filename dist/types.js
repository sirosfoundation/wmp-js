/**
 * WMP protocol types — mirrors go-wmp/pkg/wmp/types.go and methods.go.
 */
export const VERSION = "0.1";
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
    Resolve: "wmp.resolve",
};
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
};
// Close reason constants.
export const CloseReason = {
    Complete: "complete",
    Timeout: "timeout",
    Error: "error",
    UserCancelled: "user_cancelled",
};
export const AckStatus = {
    Received: "received",
    Read: "read",
    Processed: "processed",
    Failed: "failed",
};
export const FlowType = {
    Approval: "approval",
    Sign: "sign",
    Message: "message",
};
export const CancelReason = {
    UserCancelled: "user_cancelled",
    Superseded: "superseded",
    NoLongerNeeded: "no_longer_needed",
};
export const ResolveType = {
    VCTM: "vctm",
    IssuerMetadata: "issuer_metadata",
    Trust: "trust",
    Endpoint: "endpoint",
    OpenIDFederation: "openid_federation",
};
