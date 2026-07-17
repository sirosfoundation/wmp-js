/**
 * WMP Evidence types — ETSI EN 319 522 (QERDS) alignment.
 * See wmp-evidence.md for the specification.
 */

// ---------------------------------------------------------------------------
// Evidence event types
// ---------------------------------------------------------------------------

export const EvidenceEvent = {
  // Submission
  Submitted: "submitted",
  SubmissionAccepted: "submission_accepted",
  SubmissionRejected: "submission_rejected",
  // Relay
  RelayAccepted: "relay_accepted",
  RelayFailed: "relay_failed",
  // Delivery
  Delivered: "delivered",
  DeliveryFailed: "delivery_failed",
  // Retrieval
  Retrieved: "retrieved",
  RetrievalFailed: "retrieval_failed",
  ContentAccessTracked: "content_access_tracked",
  // Acceptance
  Accepted: "accepted",
  Rejected: "rejected",
  AcceptanceExpired: "acceptance_expired",
  // Consignment
  ContentHandover: "content_handover",
  ContentHandoverFailed: "content_handover_failed",
  // Notification
  NotificationSent: "notification_sent",
  NotificationFailed: "notification_failed",
  NotificationDelivered: "notification_delivered",
  // Gateway
  RelayToExternal: "relay_to_external",
  RelayToExternalFailed: "relay_to_external_failed",
  ReceivedFromExternal: "received_from_external",
} as const;

export type EvidenceEventType = (typeof EvidenceEvent)[keyof typeof EvidenceEvent];

// ---------------------------------------------------------------------------
// Evidence event reason codes
// ---------------------------------------------------------------------------

export const EventReasonCode = {
  PolicyViolation: "policy_violation",
  QuotaExceeded: "quota_exceeded",
  InvalidFormat: "invalid_format",
  InvalidRecipient: "invalid_recipient",
  InsufficientAssurance: "insufficient_assurance",
  ConsignmentModeUnsupported: "consignment_mode_unsupported",
  PolicyUnsupported: "policy_unsupported",
  RecipientRejected: "recipient_rejected",
  Timeout: "timeout",
  SystemError: "system_error",
  DelegationInvalid: "delegation_invalid",
} as const;

// ---------------------------------------------------------------------------
// Evidence types
// ---------------------------------------------------------------------------

export interface EvidenceEventReason {
  code: string;
  text?: string;
  details?: Record<string, unknown>;
}

export interface EvidenceIssuer {
  id: string;
  name?: string;
  country?: string;
}

export interface ExternalSystem {
  type: string;
  id: string;
}

export interface ExternalErds {
  id: string;
  name?: string;
  policy?: string;
}

export interface EvidenceNotifyParams {
  wmp: import("./types.js").Metadata;
  evidence_id: string;
  event_type: string;
  evidence_version: string;
  timestamp: string;
  message_id?: string;
  session_id?: string;
  sender?: string;
  recipient?: string;
  event_reason?: EvidenceEventReason;
  original_sender_delegate?: { id: string; identity_attributes?: Record<string, unknown> };
  original_recipient_delegate?: { id: string; identity_attributes?: Record<string, unknown> };
  submission_time?: string;
  evidence_issuer_policy?: string[];
  evidence_issuer?: EvidenceIssuer;
  sender_assurance_level?: string;
  recipient_assurance_level?: string;
  sender_identity_attributes?: Record<string, unknown>;
  recipient_identity_attributes?: Record<string, unknown>;
  evidence_refers_to_recipient?: string;
  external_system?: ExternalSystem;
  external_erds?: ExternalErds;
  transaction_log?: string;
  extensions?: Record<string, unknown>;
}
