/**
 * WMP OpenID4x profile — mirrors go-wmp/pkg/wmp/openid4x/openid4x.go.
 *
 * Provides OID4VCI (credential issuance) and OID4VP (credential presentation)
 * flow handling via the WMP profile system.
 */

import type {
  FlowStartParams,
  FlowStartResult,
  FlowActionParams,
  FlowActionResult,
  FlowProgressParams,
  FlowCompleteParams,
  FlowErrorParams,
  ResolveParams,
  ResolveResult,
} from "./types.js";
import type {
  Profile,
  PeerContext,
  FlowHandler,
  ResolveHandler,
} from "./profile.js";
import { WMPError } from "./jsonrpc.js";
import { ErrorCode } from "./types.js";

// ---------------------------------------------------------------------------
// Flow type constants
// ---------------------------------------------------------------------------

export const OID4FlowType = {
  OID4VCI: "oid4vci",
  OID4VP: "oid4vp",
} as const;

// ---------------------------------------------------------------------------
// Step constants for OID4VCI flows
// ---------------------------------------------------------------------------

export const VCIStep = {
  ParsingOffer: "parsing_offer",
  ResolvingMetadata: "resolving_metadata",
  MetadataFetched: "metadata_fetched",
  EvaluatingTrust: "evaluating_trust",
  TrustEvaluated: "trust_evaluated",
  AwaitingOfferAcceptance: "awaiting_offer_acceptance",
  AwaitingTxCode: "awaiting_tx_code",
  AuthorizationPending: "authorization_pending",
  GeneratingProof: "generating_proof",
  RequestingCredential: "requesting_credential",
  CredentialReceived: "credential_received",
} as const;

// ---------------------------------------------------------------------------
// Step constants for OID4VP flows
// ---------------------------------------------------------------------------

export const VPStep = {
  ParsingRequest: "parsing_request",
  RequestParsed: "request_parsed",
  EvaluatingTrust: "evaluating_trust",
  TrustEvaluated: "trust_evaluated",
  MatchingCredentials: "matching_credentials",
  AwaitingConsent: "awaiting_consent",
  GeneratingPresentation: "generating_presentation",
} as const;

// ---------------------------------------------------------------------------
// Action constants
// ---------------------------------------------------------------------------

export const OID4Action = {
  AcceptOffer: "accept_offer",
  ProvideTxCode: "provide_tx_code",
  Authorize: "authorize",
  SelectCredentials: "select_credentials",
  Cancel: "cancel",
} as const;

// ---------------------------------------------------------------------------
// Capability types
// ---------------------------------------------------------------------------

export interface OID4VCICapability {
  supported_grants: string[];
  supported_formats: string[];
  supported_proof_types?: string[];
  batch_issuance?: boolean;
}

export interface OID4VPCapability {
  supported_response_modes: string[];
  supported_formats: string[];
  supported_algorithms?: string[];
}

// ---------------------------------------------------------------------------
// Config and handler types
// ---------------------------------------------------------------------------

export type FlowStartHandler = (
  params: FlowStartParams,
) => Promise<FlowStartResult>;

export type ActionHandler = (
  params: FlowActionParams,
) => Promise<FlowActionResult>;

export interface OpenID4xConfig {
  /** OID4VCI capability. Omit to disable issuance. */
  oid4vci?: OID4VCICapability;

  /** OID4VP capability. Omit to disable presentation. */
  oid4vp?: OID4VPCapability;

  /** Called when an OID4VCI flow starts. */
  onVCIStart?: FlowStartHandler;

  /** Called when an action arrives for an OID4VCI flow. */
  onVCIAction?: ActionHandler;

  /** Called when an OID4VP flow starts. */
  onVPStart?: FlowStartHandler;

  /** Called when an action arrives for an OID4VP flow. */
  onVPAction?: ActionHandler;
}

// ---------------------------------------------------------------------------
// OpenID4x Profile
// ---------------------------------------------------------------------------

/**
 * OpenID4xProfile implements Profile, FlowHandler, and ResolveHandler
 * for OID4VCI and OID4VP credential exchange flows.
 *
 * Usage:
 *   const profile = new OpenID4xProfile({ oid4vci: {...}, oid4vp: {...} });
 *   peer.use(profile);
 */
export class OpenID4xProfile implements Profile, FlowHandler, ResolveHandler {
  readonly name = "openid4x";
  private config: OpenID4xConfig;
  private peer?: PeerContext;
  private flowTypeMap = new Map<string, string>();

  constructor(config: OpenID4xConfig) {
    this.config = config;
  }

  // --- Profile ---

  capabilities(): string[] {
    const caps: string[] = [];
    if (this.config.oid4vci) caps.push("oid4vci");
    if (this.config.oid4vp) caps.push("oid4vp");
    return caps;
  }

  init(ctx: PeerContext): void {
    this.peer = ctx;
  }

  // --- FlowHandler ---

  flowTypes(): string[] {
    const types: string[] = [];
    if (this.config.oid4vci) types.push(OID4FlowType.OID4VCI);
    if (this.config.oid4vp) types.push(OID4FlowType.OID4VP);
    return types;
  }

  async startFlow(params: FlowStartParams): Promise<FlowStartResult> {
    switch (params.flow_type) {
      case OID4FlowType.OID4VCI: {
        this.flowTypeMap.set(params.flow_id, OID4FlowType.OID4VCI);
        if (this.config.onVCIStart) {
          return this.config.onVCIStart(params);
        }
        return {
          wmp: params.wmp,
          flow_id: params.flow_id,
          flow_type: params.flow_type,
        };
      }
      case OID4FlowType.OID4VP: {
        this.flowTypeMap.set(params.flow_id, OID4FlowType.OID4VP);
        if (this.config.onVPStart) {
          return this.config.onVPStart(params);
        }
        return {
          wmp: params.wmp,
          flow_id: params.flow_id,
          flow_type: params.flow_type,
        };
      }
      default:
        throw new WMPError(ErrorCode.FlowError, `Unsupported flow type: ${params.flow_type}`);
    }
  }

  async handleAction(params: FlowActionParams): Promise<FlowActionResult> {
    const flowType = this.flowTypeMap.get(params.flow_id);
    switch (flowType) {
      case OID4FlowType.OID4VCI:
        if (this.config.onVCIAction) {
          return this.config.onVCIAction(params);
        }
        break;
      case OID4FlowType.OID4VP:
        if (this.config.onVPAction) {
          return this.config.onVPAction(params);
        }
        break;
    }
    return {
      wmp: params.wmp,
      flow_id: params.flow_id,
      action: params.action,
      status: "accepted",
    };
  }

  handleProgress(_params: FlowProgressParams): void {
    // Override via middleware or subclass.
  }

  handleComplete(params: FlowCompleteParams): void {
    this.flowTypeMap.delete(params.flow_id);
  }

  handleError(params: FlowErrorParams): void {
    this.flowTypeMap.delete(params.flow_id);
  }

  // --- ResolveHandler ---

  resolveTypes(): string[] {
    return ["vctm", "issuer_metadata"];
  }

  async handleResolve(_params: ResolveParams): Promise<ResolveResult> {
    throw new WMPError(
      ErrorCode.CapabilityNotSupported,
      "OpenID4x resolve not implemented",
    );
  }
}
