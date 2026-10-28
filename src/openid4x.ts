/**
 * WMP OpenID4x profile — mirrors go-wmp/pkg/wmp/openid4x/openid4x.go.
 *
 * Provides OID4VCI (credential issuance) and OID4VP (credential presentation)
 * flow handling via the WMP profile system.
 */

import type {
  Capabilities,
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
import { Method, ErrorCode, VERSION } from "./types.js";
import type {
  Profile,
  PeerContext,
  FlowHandler,
  ResolveHandler,
  MethodHandler,
} from "./profile.js";
import { WMPError } from "./jsonrpc.js";
import { unsupportedError } from "./errors.js";
import { validateMatchResult } from "./completion.js";
import {
  CAPABILITY_TRANSACTION_DATA,
  SignFlow,
  dcqlQueryIds,
  completeSubFlow,
  parseMatchStartParams,
  parseSignSubFlowParams,
  rejectSubFlow,
  transactionDataUnsupportedError,
  type MatchResult,
  type MatchStartParams,
  type TransactionDataCapability,
} from "./signflow.js";

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
 * A single transaction data entry of the verifier's OID4VP request (EC TS12),
 * as the orchestrator sends it in a sign_presentation sub-flow (profile
 * Section 3.2.5).
 *
 * A presentation binds to `raw`, not to the object it decodes to: OID4VP 1.0
 * (Appendix B) hashes the base64url string as received, and re-encoding the
 * decoded object does not reproduce it. A wallet hashes `raw`
 * ({@link transactionDataHash}), decodes it itself and refuses an entry whose
 * other members disagree with the decoding ({@link checkTransactionDataEntry}).
 */
export interface TransactionData {
  /** The entry exactly as the verifier sent it: the base64url string. */
  raw: string;
  /** `type` of the decoded entry. */
  type: string;
  /** `credential_ids` of the decoded entry: the DCQL credential query ids it is bound to. */
  credential_ids: string[];
  /** `payload` of the decoded entry (EC TS12 Section 4.2). For validation and display; never hash it. */
  payload?: Record<string, unknown>;
  /**
   * The verifier's acceptable hash algorithms for this entry (OID4VP). An
   * array on the wire; a bare string is accepted from older peers. Read it
   * through {@link transactionDataHashesAlgs}.
   */
  transaction_data_hashes_alg?: string[] | string;
  /** @deprecated TS12 types carry their members in `payload`. */
  params?: Record<string, unknown>;
  /** @deprecated Non-standard; use transaction_data_hashes_alg. */
  hash_alg?: string;
}

/**
 * Normalizes TransactionData.transaction_data_hashes_alg to an array (the
 * spec shape); a bare string from an older peer becomes a one-element array.
 * Anything else (including empty strings and non-string array members) is
 * dropped.
 */
export function transactionDataHashesAlgs(td: Pick<TransactionData, "transaction_data_hashes_alg">): string[] {
  const v: unknown = td.transaction_data_hashes_alg;
  if (typeof v === "string") return v === "" ? [] : [v];
  if (Array.isArray(v)) return v.filter((x): x is string => typeof x === "string" && x !== "");
  return [];
}

/** One element of `credentials_to_include`: the credential query the user consented to answer, and nothing else. */
export interface CredentialToInclude {
  credential_query_id: string;
}

/** `credential_response_encryption` of a generate_proof request (profile 3.1.5.1). */
export interface CredentialResponseEncryption {
  alg: string;
  enc: string;
  required: boolean;
}

/**
 * Params of a `sign` flow.start the wallet answers (Core Section 6, profile
 * Sections 3.1.5, 3.2.5 and 7). Mirrors go-wmp openid4x.SignSubFlowParams
 * (v0.11.0) member for member; members a peer sends that are not listed here
 * are kept by {@link parseSignSubFlowParams}, never dropped.
 */
export interface SignSubFlowParams {
  /** generate_proof, sign_presentation, decrypt_credential_response, sign_client_auth, ... */
  action: string;
  /** The oid4vci/oid4vp flow this sub-flow belongs to. Absent for a plain Core sign flow. */
  parent_flow_id?: string;
  nonce?: string;
  audience?: string;
  proof_type?: string;
  /** JWT `iss` for generated proof JWTs (typically the OAuth client_id). */
  issuer?: string;
  /** The issuer's proof_types_supported map. */
  proof_types_supported?: Record<string, unknown>;
  /** Number of proofs to generate (batch size); 1 when absent. */
  count?: number;
  /** Verifier's response endpoint (mdoc session transcript; sign_presentation). */
  response_uri?: string;
  verifier_jwk_thumbprint?: string;
  verifier_session_id?: string;
  /** The verifier's client_metadata, verbatim (profile 7.1). */
  client_metadata?: Record<string, unknown>;
  /** The request as the engine validated it (profile 7.5). Carries no trust verdict. */
  verified_request?: Record<string, unknown>;
  /** Recipient the wallet encrypts the JARM response to (direct_post.jwt; profile 7.7). */
  response_encryption?: Record<string, unknown>;
  state?: string;
  /** The OID4VP response_mode; required in the key binding JWT of an SCA presentation. */
  response_mode?: string;
  /** The request's transaction data, in the verifier's order. */
  transaction_data?: TransactionData[];
  /** The credential queries the user consented to answer; nothing but the query id of each. */
  credentials_to_include?: CredentialToInclude[];
  /** The handle of the select_credentials action, handed back unchanged. */
  selection_handle?: string;
  /** Renewal: sign with the existing key identified by this kid. */
  reissuance_kid?: string;
  // sign_client_auth
  htm?: string;
  htu?: string;
  dpop_nonce?: string;
  ath?: string;
  key_id?: string;
  attestation_challenge?: string;
  // generate_proof extensions (profile 3.1.5.1)
  credential_response_encryption?: CredentialResponseEncryption;
  auxiliary_data_to_issuer?: Record<string, unknown>[];
  credential_type?: string;
  credential_issuer?: string;
  // decrypt_credential_response
  jwe?: string;
  deferred?: boolean;
  /** Members this library does not model are preserved. */
  [member: string]: unknown;
}

/** Accept offer action params (OID4VCI). */
export interface SelectionAction {
  selected_indices: number[];
  consent: boolean;
}

/**
 * `select_credentials` action params (profile 3.2.3.1): a closed set. The
 * orchestrator learns that the user consented and for which of the verifier's
 * own query ids; never a credential, claim, count or free text. Build with
 * {@link buildSelectCredentials}, check with {@link validateSelectCredentialsParams}.
 */
export interface ConsentAction {
  consent: boolean;
  /** At least one element when consent is true; absent or empty otherwise. */
  selections?: CredentialSelection[];
}

/** One consented credential query and the opaque per-flow handle. Both members, nothing else. */
export interface CredentialSelection {
  /** The `id` of a credential query of the verifier's request. */
  query_id: string;
  /** 22+ base64url characters, the same in every element: the match result's handle, or one the wallet chose. */
  selection_handle: string;
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

export type CredentialNotificationHandler = (
  params: CredentialNotificationParams,
) => void | Promise<void>;

export interface OpenID4xConfig {
  /** OID4VCI capability. Omit to disable issuance. */
  oid4vci?: OID4VCICapability;

  /** OID4VP capability. Omit to disable presentation. */
  oid4vp?: OID4VPCapability;

  /**
   * transaction_data capability (profile 2.3). Offer it only if the wallet does
   * everything profile 3.2.5 requires: hash `raw`, validate and display the
   * decoded entry, fail closed. Omit to not advertise it; a sign sub-flow that
   * carries transaction_data is then refused with -31005.
   */
  transactionData?: TransactionDataCapability;

  /**
   * Called for each `sign` sub-flow the orchestrator starts (generate_proof,
   * sign_presentation, decrypt_credential_response, ...), after the start was
   * validated and answered. Answer through the SignFlow: complete(), reject()
   * (-31006 rejected), fail() or unsupportedTransactionData(). A throw ends the
   * sub-flow with wmp.flow.error. Without it the profile does not handle `sign`.
   */
  onSign?: (flow: SignFlow) => void | Promise<void>;

  /**
   * Answers a `match` flow (profile 3.3): evaluate the DCQL query locally and
   * return the closed result. Throw {@link SubFlowRejectedError} when the user
   * declines; any other throw answers satisfiable=false, code "error". The result
   * is validated before it is sent. Needs `oid4vp`.
   */
  onMatch?: (params: MatchStartParams) => MatchResult | Promise<MatchResult>;

  /** Called when an OID4VCI flow starts. */
  onVCIStart?: FlowStartHandler;

  /** Called when an action arrives for an OID4VCI flow. */
  onVCIAction?: ActionHandler;

  /** Called when an OID4VP flow starts. */
  onVPStart?: FlowStartHandler;

  /** Called when an action arrives for an OID4VP flow. */
  onVPAction?: ActionHandler;

  /**
   * Called when a validated wmp.credential.notification arrives.
   * The notification_id is guaranteed to have been registered for an
   * outstanding OID4VCI flow (see registerCredentialNotification).
   */
  onCredentialNotification?: CredentialNotificationHandler;

  /**
   * Require notification_ids to be registered before accepting
   * wmp.credential.notification. Default: true.
   */
  requireRegisteredNotification?: boolean;
}

/** Thrown from `onMatch` when the user declines: the match flow ends with -31006 rejected. */
export class SubFlowRejectedError extends Error {
  constructor() {
    super("sub-flow rejected");
    this.name = "SubFlowRejectedError";
  }
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
export class OpenID4xProfile
  implements Profile, FlowHandler, ResolveHandler, MethodHandler
{
  readonly name = "openid4x";
  private config: OpenID4xConfig;
  private peer?: PeerContext;
  private flowTypeMap = new Map<string, string>();
  private registeredNotifications = new Map<string, string>(); // flow_id -> notification_id

  constructor(config: OpenID4xConfig) {
    this.config = config;
  }

  // --- Profile ---

  capabilities(): string[] {
    const caps: string[] = [];
    if (this.config.oid4vci) caps.push("oid4vci");
    if (this.config.oid4vp) caps.push("oid4vp");
    if (this.config.transactionData) caps.push(CAPABILITY_TRANSACTION_DATA);
    return caps;
  }

  /**
   * The capability descriptors for session negotiation (mirror of go-wmp
   * CapabilityDescriptors): "oid4vci", "oid4vp" and "transaction_data", each
   * present only when configured, required list members as [] rather than
   * missing. Throws for a transaction_data descriptor that lists no version:
   * it would advertise a capability no peer can use.
   */
  capabilityDescriptors(): Capabilities {
    const caps: Capabilities = {};
    const c = this.config;
    if (c.oid4vci) caps.oid4vci = { ...c.oid4vci, supported_grants: c.oid4vci.supported_grants ?? [], supported_formats: c.oid4vci.supported_formats ?? [] };
    if (c.oid4vp) caps.oid4vp = { ...c.oid4vp, supported_response_modes: c.oid4vp.supported_response_modes ?? [], supported_formats: c.oid4vp.supported_formats ?? [] };
    if (c.transactionData) {
      if (!Array.isArray(c.transactionData.versions) || c.transactionData.versions.length === 0) {
        throw new Error("openid4x: transaction_data descriptor lists no versions");
      }
      caps[CAPABILITY_TRANSACTION_DATA] = { ...c.transactionData };
    }
    return caps;
  }

  init(ctx: PeerContext): void {
    this.peer = ctx;
  }

  // --- MethodHandler ---

  methods(): string[] {
    if (!this.config.oid4vci) return [];
    return [Method.CredentialNotification];
  }

  async handleMethod(method: string, params: unknown): Promise<unknown> {
    if (method !== Method.CredentialNotification) {
      throw new WMPError(ErrorCode.MethodNotFound, `Unknown method: ${method}`);
    }

    const p = params as CredentialNotificationParams;
    if (!p.flow_id || !p.notification_id) {
      throw new WMPError(
        ErrorCode.InvalidParams,
        "Missing flow_id or notification_id",
      );
    }

    const requireRegistered =
      this.config.requireRegisteredNotification ?? true;
    if (requireRegistered) {
      const expected = this.registeredNotifications.get(p.flow_id);
      if (expected !== p.notification_id) {
        throw new WMPError(
          ErrorCode.NotAuthorized,
          "Unknown or unexpected credential notification_id",
        );
      }
    }

    if (this.config.onCredentialNotification) {
      await this.config.onCredentialNotification(p);
    }

    // Consume the notification so it cannot be replayed.
    this.registeredNotifications.delete(p.flow_id);
    return { wmp: p.wmp, acknowledged: true };
  }

  /**
   * Register a notification_id that was returned for an OID4VCI flow.
   * This allows wmp.credential.notification messages to be validated.
   */
  registerCredentialNotification(
    flowId: string,
    notificationId: string,
  ): void {
    this.registeredNotifications.set(flowId, notificationId);
  }

  // --- FlowHandler ---

  flowTypes(): string[] {
    const types: string[] = [];
    if (this.config.oid4vci) types.push(OID4FlowType.OID4VCI);
    if (this.config.oid4vp) types.push(OID4FlowType.OID4VP);
    if (this.config.onSign) types.push("sign");
    if (this.config.onMatch && this.config.oid4vp) types.push("match");
    return types;
  }

  /** Each flow type needs the capability of the same name (Core 6.5 item 2; profile Section 2). */
  requiredCapability(flowType: string): string {
    switch (flowType) {
      case OID4FlowType.OID4VCI:
        return "oid4vci";
      case OID4FlowType.OID4VP:
      case "match": // a nested flow of an oid4vp flow, defined for the oid4vp capability (profile 3.3)
        return "oid4vp";
      default:
        return "";
    }
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
      case "sign": {
        const sp = parseSignSubFlowParams(params.params);
        // Transaction data the wallet did not offer to process: refuse, never sign without binding.
        if (sp.transaction_data && sp.transaction_data.length > 0 && !this.config.transactionData) {
          throw transactionDataUnsupportedError();
        }
        const flow = new SignFlow(this.peer!, params.wmp, params.flow_id, sp);
        this.defer(async () => {
          try {
            await this.config.onSign!(flow);
          } catch (err) {
            // A fixed message: whatever the callback threw may carry credential data.
            if (err instanceof WMPError) await flow.fail(err.code, err.rpcMessage, err.data);
            else await flow.fail(ErrorCode.FlowError, "Sign failed");
          }
        });
        return { wmp: params.wmp, flow_id: params.flow_id, flow_type: params.flow_type };
      }
      case "match": {
        const mp = parseMatchStartParams(params.params);
        this.defer(() => this.runMatch(params, mp));
        return { wmp: params.wmp, flow_id: params.flow_id, flow_type: params.flow_type };
      }
      default:
        throw unsupportedError(params.flow_type);
    }
  }

  /** Runs after the flow.start response was sent, so the completion never overtakes it. */
  private defer(fn: () => Promise<void>): void {
    setTimeout(() => {
      fn().catch(() => {
        /* the answer could not be sent: the orchestrator's flow timeout applies */
      });
    }, 0);
  }

  private async runMatch(start: FlowStartParams, mp: MatchStartParams): Promise<void> {
    const peer = this.peer!;
    let result: MatchResult;
    try {
      result = await this.config.onMatch!(mp);
      validateMatchResult(result, dcqlQueryIds(mp.dcql_query));
    } catch (err) {
      if (err instanceof SubFlowRejectedError) {
        await rejectSubFlow(peer, start.wmp, start.flow_id);
        return;
      }
      // The wallet could not evaluate the query (or produced a result the
      // orchestrator would refuse): code is the whole reason, never the cause.
      result = { satisfiable: false, code: "error" };
    }
    await completeSubFlow(peer, start.wmp, start.flow_id, result, (r) => validateMatchResult(r, dcqlQueryIds(mp.dcql_query)));
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
