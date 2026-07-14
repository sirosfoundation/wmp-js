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
  Metadata,
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
import { ErrorCode, VERSION } from "./types.js";

// ---------------------------------------------------------------------------
// Credential format constants — aligned with wallet-common VerifiableCredentialFormat
// ---------------------------------------------------------------------------

export const CredentialFormat = {
  VC_SDJWT: "vc+sd-jwt",
  DC_SDJWT: "dc+sd-jwt",
  MSO_MDOC: "mso_mdoc",
  JWT_VC_JSON: "jwt_vc_json",
} as const;

export type CredentialFormatType = (typeof CredentialFormat)[keyof typeof CredentialFormat];

export const allFormats: CredentialFormatType[] = [
  CredentialFormat.VC_SDJWT,
  CredentialFormat.DC_SDJWT,
  CredentialFormat.MSO_MDOC,
  CredentialFormat.JWT_VC_JSON,
];

export function isValidFormat(format: string): format is CredentialFormatType {
  return allFormats.includes(format as CredentialFormatType);
}

// ---------------------------------------------------------------------------
// Grant type constants for OID4VCI
// ---------------------------------------------------------------------------

export const GrantType = {
  AuthorizationCode: "authorization_code",
  PreAuthorizedCode: "pre-authorized_code",
} as const;

// ---------------------------------------------------------------------------
// Response mode constants for OID4VP
// ---------------------------------------------------------------------------

export const ResponseMode = {
  DirectPost: "direct_post",
  DirectPostJWT: "direct_post.jwt",
  DCAPI: "dc_api",
  DCAPIJWT: "dc_api.jwt",
} as const;

// ---------------------------------------------------------------------------
// Proof type constants
// ---------------------------------------------------------------------------

export const ProofType = {
  JWT: "jwt",
  Attestation: "attestation",
  CWT: "cwt",
} as const;

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
// Credential configuration types
// ---------------------------------------------------------------------------

export interface CredentialDisplay {
  name: string;
  locale?: string;
  description?: string;
  logo_uri?: string;
  logo_alt_text?: string;
  background_color?: string;
  text_color?: string;
}

export interface CredentialConfigurationSupported {
  format: string;
  scope?: string;
  vct?: string;     // sd-jwt formats
  doctype?: string;  // mso_mdoc
  cryptographic_binding_methods_supported?: string[];
  credential_signing_alg_values_supported?: string[];
  proof_types_supported?: Record<string, unknown>;
  display?: CredentialDisplay[];
}

export interface CredentialResult {
  format: string;
  credential: string;
  vct?: string;
  c_nonce?: string;
  notification_id?: string;
}

/** OID4VCI §10 credential lifecycle events. */
export type CredentialEvent = "credential_accepted" | "credential_failure";

/** Params for wmp.credential.notification. */
export interface CredentialNotificationParams {
  wmp: Metadata;
  flow_id: string;
  notification_id: string;
  event: CredentialEvent;
  event_description?: string;
}

export interface VPTokenResult {
  vp_token?: string | string[];
  presentation_submission?: unknown;
  response_code?: string;
}

// ---------------------------------------------------------------------------
// OID4VCI flow start params — the protocol-specific payload inside
// FlowStartParams.params for OID4VCI flows.
// ---------------------------------------------------------------------------

/**
 * Client attestation credentials (WIA + PoP) for issuer authentication.
 * Produced by a {@link ClientAttestationProvider}.
 */
export interface ClientAttestation {
  /** WIA JWT (typ: oauth-client-attestation+jwt) */
  client_attestation: string;
  /** PoP JWT (typ: oauth-client-attestation-pop+jwt) signed by wallet instance key */
  client_attestation_pop: string;
}

/**
 * Provider interface for obtaining OAuth client attestation credentials.
 *
 * Callers implement this to decouple wmp-js from any specific wallet backend.
 * The provider is responsible for:
 * 1. Obtaining a WIA JWT from the wallet provider (implementation-defined)
 * 2. Signing the PoP JWT with the wallet instance key (aud = issuer AS URL)
 *
 * Example implementations:
 * - SIROS: calls /wallet-provider/wia/generate, signs PoP with passkey-PRF key
 * - EUDI: calls the PID provider's WIA endpoint, signs PoP with device key
 * - Test: returns static test JWTs
 */
export interface ClientAttestationProvider {
  /**
   * Get attestation credentials for a specific issuer.
   * @param audience - The issuer's AS URL (used as PoP aud claim)
   * @returns WIA + PoP JWTs, or null if attestation is not available/required
   */
  getAttestation(audience: string): Promise<ClientAttestation | null>;
}

/**
 * OID4VCI-specific parameters for wmp.flow.start.
 * Passed as the `params` field of FlowStartParams when flow_type = "oid4vci".
 *
 * Client attestation fields support draft-ietf-oauth-attestation-based-client-auth-04:
 * - `client_attestation`: WIA JWT from the provider
 * - `client_attestation_pop`: PoP JWT signed by the wallet instance key (aud = AS URL)
 *
 * The instance key is held client-side (never on the backend).
 * The backend forwards these as HTTP headers without modification.
 */
/** Common fields shared by all OID4VCI flow param variants. */
interface OID4VCIFlowParamsBase {
  /** OAuth redirect URI for authorization code flow */
  redirect_uri?: string;

  // --- Client attestation (draft-ietf-oauth-attestation-based-client-auth-04) ---

  /** WIA JWT (typ: oauth-client-attestation+jwt) obtained via ClientAttestationProvider */
  client_attestation?: string;
  /** PoP JWT (typ: oauth-client-attestation-pop+jwt) signed by wallet instance key */
  client_attestation_pop?: string;

  // --- Resumption fields (same-tab redirect flow) ---

  /** Authorization code from OAuth redirect */
  auth_code?: string;
  /** PKCE code verifier (saved by client before redirect) */
  code_verifier?: string;
}

/** OID4VCI params with an inline credential offer. */
export interface OID4VCIFlowParamsWithOffer extends OID4VCIFlowParamsBase {
  /** Credential offer URI (openid-credential-offer://...) */
  offer: string;
  credential_offer_uri?: never;
}

/** OID4VCI params with a credential offer by reference. */
export interface OID4VCIFlowParamsWithURI extends OID4VCIFlowParamsBase {
  offer?: never;
  /** Credential offer URI by reference (https://...) */
  credential_offer_uri: string;
}

/**
 * OID4VCI-specific parameters for wmp.flow.start.
 * Passed as the `params` field of FlowStartParams when flow_type = "oid4vci".
 *
 * Exactly one of `offer` or `credential_offer_uri` must be provided.
 */
export type OID4VCIFlowParams = OID4VCIFlowParamsWithOffer | OID4VCIFlowParamsWithURI;

/**
 * OID4VP-specific parameters for wmp.flow.start.
 * Passed as the `params` field of FlowStartParams when flow_type = "oid4vp".
 */
export interface OID4VPFlowParams {
  /** Request URI (openid4vp://...) */
  request_uri?: string;
  /** Request URI by reference (https://...) */
  request_uri_ref?: string;
}

/**
 * Helper to build WMP FlowStartParams for an OID4VCI flow.
 * If attestation is provided, it is included in the params.
 */
export function buildVCIFlowStart(
  sessionId: string,
  flowId: string,
  params: OID4VCIFlowParams,
  timeout?: number,
): FlowStartParams {
  return {
    wmp: { version: VERSION, session_id: sessionId },
    flow_type: OID4FlowType.OID4VCI,
    flow_id: flowId,
    params,
    timeout,
  };
}

/**
 * Helper to build VCI flow params with attestation from a provider.
 * Calls the provider to obtain WIA + PoP, then merges into the params.
 *
 * @param provider - The attestation provider (caller-supplied)
 * @param audience - The issuer's AS URL for PoP audience binding
 * @param params - Base OID4VCI flow params (offer, redirect_uri, etc.)
 * @returns params with attestation fields populated (or unchanged if provider returns null)
 */
export async function withAttestation(
  provider: ClientAttestationProvider,
  audience: string,
  params: OID4VCIFlowParams,
): Promise<OID4VCIFlowParams> {
  const attestation = await provider.getAttestation(audience);
  if (!attestation) return params;
  return {
    ...params,
    client_attestation: attestation.client_attestation,
    client_attestation_pop: attestation.client_attestation_pop,
  };
}

/**
 * TransactionData represents a single transaction data object from
 * the verifier's OID4VP authorization request (TS12/SCA).
 */
export interface TransactionData {
  type: string;
  params?: Record<string, unknown>;
  /** Credential IDs this transaction data applies to */
  credential_ids?: string[];
  /** Hash algorithm for transaction_data_hashes */
  hash_alg?: string;
  /** Algorithm identifier for the hashes claim in KB-JWT */
  transaction_data_hashes_alg?: string;
}

export interface SignSubFlowParams {
  action: string;
  nonce: string;
  audience: string;
  proof_type?: string;
  parent_flow_id: string;
  transaction_data?: TransactionData[];
}

export interface SelectionAction {
  selected_indices: number[];
  consent: boolean;
}

export interface ConsentAction {
  selections: CredentialSelection[];
  consent: boolean;
}

export interface CredentialSelection {
  credential_id: string;
  credential_query_id?: string;
  disclosed_claims: string[];
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
