/**
 * Wallet side of the WMP sign sub-flows and the match flow (profile Sections
 * 3.1.5, 3.2.5, 3.2.6 and 3.3) — the responder counterpart of go-wmp's
 * orchestrator-side FlowContext.RequestSign / RequestMatch.
 */

import { sha256, sha384, sha512 } from "@noble/hashes/sha2.js";
import { CompletionResultError, validateCompletionResult } from "./completion.js";
import { isSelectionHandle } from "./consent.js";
import { unsupportedError } from "./errors.js";
import { WMPError } from "./jsonrpc.js";
import { ErrorCode, Method, VERSION, type Capabilities, type Metadata } from "./types.js";
import type { PeerContext } from "./profile.js";
import type { SignSubFlowParams, TransactionData } from "./openid4x.js";

// ---------------------------------------------------------------------------
// transaction_data capability (profile 2.3)
// ---------------------------------------------------------------------------

/** The capability a wallet offers when it processes OID4VP transaction_data end to end. */
export const CAPABILITY_TRANSACTION_DATA = "transaction_data";

/** First version of the transaction_data capability. */
export const TRANSACTION_DATA_VERSION_1 = 1;

/** Parameters of the `transaction_data` capability. */
export interface TransactionDataCapability {
  /** Versions of the capability the wallet implements. A non-empty array. */
  versions: number[];
  /** transaction_data_hashes_alg names the wallet can compute, e.g. "sha-256". */
  hash_algs?: string[];
}

/**
 * Whether `caps` contains a transaction_data capability that lists `version`
 * (go-wmp Capabilities.OffersTransactionData). Absence, an unparsable value or a
 * list without the version all mean "not offered". Use it on what the peer
 * OFFERED (`capabilities_offered`), never on the negotiated result: negotiation
 * may fall back to all of the responder's capabilities when a peer offers none,
 * which would read as support the peer never claimed.
 */
export function offersTransactionData(caps: Capabilities | undefined, version: number = TRANSACTION_DATA_VERSION_1): boolean {
  const raw: unknown = caps !== undefined && Object.prototype.hasOwnProperty.call(caps, CAPABILITY_TRANSACTION_DATA) ? caps[CAPABILITY_TRANSACTION_DATA] : undefined;
  // A malformed descriptor is not an offer: fail closed on every member we know.
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return false;
  const c = raw as { versions?: unknown; hash_algs?: unknown };
  if (!Array.isArray(c.versions) || c.versions.length === 0 || !c.versions.every((v) => Number.isInteger(v) && (v as number) >= 1)) return false;
  if (c.hash_algs !== undefined && (!Array.isArray(c.hash_algs) || !c.hash_algs.every((a) => typeof a === "string" && a !== ""))) return false;
  return c.versions.includes(version);
}

/**
 * The `data` of the -31005 a wallet answers with for transaction_data it will not
 * process: {"unsupported": "transaction_data"}, plus `redirect_uri` when the
 * verifier's response mode produced a redirect (additive, profile 2.3).
 */
export function transactionDataUnsupportedData(redirectUri?: string): Record<string, unknown> {
  return { ...(redirectUri ? { redirect_uri: redirectUri } : {}), unsupported: CAPABILITY_TRANSACTION_DATA };
}

/** The -31005 error carrying {@link transactionDataUnsupportedData}. */
export function transactionDataUnsupportedError(redirectUri?: string): WMPError {
  return unsupportedError(CAPABILITY_TRANSACTION_DATA, redirectUri ? { redirect_uri: redirectUri } : undefined);
}

// ---------------------------------------------------------------------------
// transaction_data hashing and entry checks (profile 3.2.5)
// ---------------------------------------------------------------------------

// A Map, not an object: "constructor" or "toString" must not name an algorithm.
const HASHES = new Map<string, (b: Uint8Array) => Uint8Array>([
  ["sha-256", sha256],
  ["sha-384", sha384],
  ["sha-512", sha512],
]);

/** Hash algorithms {@link transactionDataHash} computes. */
export const TRANSACTION_DATA_HASH_ALGS: readonly string[] = [...HASHES.keys()];

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new Error("not base64url");
  const pad = (4 - (s.length % 4)) % 4;
  if (pad === 3) throw new Error("impossible base64url length");
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat(pad));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/**
 * `transaction_data_hashes` element for an entry: base64url (no padding) of the
 * hash of the ASCII bytes of `raw`, exactly as received (OID4VP 1.0 Appendix B:
 * "base64url decoding is not performed before hashing"). Never hash a decoded
 * and re-serialized object. Throws for an algorithm this library does not
 * compute (the wallet then fails the sub-flow: it cannot bind) or a `raw` that is
 * not ASCII.
 */
export function transactionDataHash(raw: string, alg: string = "sha-256"): string {
  const h = HASHES.get(alg);
  if (!h) throw new Error(`unsupported transaction_data hash algorithm`);
  // eslint-disable-next-line no-control-regex
  if (!/^[\u0000-\u007f]*$/.test(raw)) throw new Error("transaction_data raw is not ASCII");
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return toBase64Url(h(bytes));
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== "object" || typeof b !== "object" || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => Object.prototype.hasOwnProperty.call(b, k) && deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/**
 * A transaction_data_hashes_alg as a list for comparison: a bare string becomes a
 * one-element list; anything else is kept as it is, malformed elements included,
 * so a disagreement hidden in a bad element cannot pass.
 */
function algList(v: unknown): unknown {
  return typeof v === "string" ? [v] : v;
}

/**
 * Decodes an entry's `raw` and returns the decoded object. The wallet validates
 * and displays THIS, not the members the orchestrator sent next to it. Throws
 * -32602 when `raw` is not base64url of a JSON object.
 */
export function decodeTransactionData(raw: string): Record<string, unknown> {
  try {
    const v: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(fromBase64Url(raw)));
    if (typeof v === "object" && v !== null && !Array.isArray(v)) return v as Record<string, unknown>;
  } catch {
    /* fall through */
  }
  throw invalidParams("transaction_data raw is not base64url of a JSON object");
}

/**
 * Refuses an entry whose members disagree with what `raw` decodes to (profile
 * 3.2.5 requirement 2): otherwise a compromised orchestrator could show one
 * transaction and bind another. Returns the decoded entry for display.
 */
export function checkTransactionDataEntry(entry: TransactionData): Record<string, unknown> {
  const d = decodeTransactionData(entry.raw);
  if (d.type !== entry.type) throw invalidParams("transaction_data type disagrees with raw");
  if (!deepEqual(d.credential_ids, entry.credential_ids)) throw invalidParams("transaction_data credential_ids disagree with raw");
  if (entry.payload !== undefined && !deepEqual(d.payload, entry.payload)) throw invalidParams("transaction_data payload disagrees with raw");
  if (entry.transaction_data_hashes_alg !== undefined && !deepEqual(algList(d.transaction_data_hashes_alg), algList(entry.transaction_data_hashes_alg))) {
    throw invalidParams("transaction_data_hashes_alg disagrees with raw");
  }
  return d;
}

// ---------------------------------------------------------------------------
// Sign sub-flow params
// ---------------------------------------------------------------------------

function invalidParams(reason: string): WMPError {
  // The reason names a member or a rule, never a value.
  return new WMPError(ErrorCode.InvalidParams, "Invalid params", { reason });
}

/** Sign actions a wallet answers: Core (generate_proof, sign_document, authorize) and the profile's. */
export const SIGN_ACTIONS: readonly string[] = [
  "generate_proof",
  "sign_document",
  "authorize",
  "sign_presentation",
  "sign_client_auth",
  "decrypt_credential_response",
];

/** Upper bound on `count` (batch size) a wallet will generate proofs for. */
export const MAX_PROOF_COUNT = 256;

const STRING_MEMBERS = [
  "nonce", "audience", "proof_type", "issuer", "response_uri", "verifier_jwk_thumbprint", "verifier_session_id",
  "state", "response_mode", "reissuance_kid", "htm", "htu", "dpop_nonce", "ath", "key_id", "attestation_challenge",
  "credential_type", "credential_issuer", "jwe",
];
const OBJECT_MEMBERS = ["proof_types_supported", "client_metadata", "verified_request", "response_encryption"];

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

/**
 * Validates the `params` of a `sign` flow.start and returns them (a shallow
 * copy that keeps members this library does not model). Throws a WMPError:
 * -32602 for a malformed member, an unknown action or the old
 * `credentials_to_include` shape; -31005 {"unsupported":"transaction_data"}
 * for an entry that lacks `raw` (the wallet cannot bind to it and MUST refuse,
 * profile 3.2.5). Error data names members, never values.
 */
export function parseSignSubFlowParams(raw: unknown): SignSubFlowParams {
  if (!isObj(raw)) throw invalidParams("params is not an object");
  const p = raw;
  if (typeof p.action !== "string" || !SIGN_ACTIONS.includes(p.action)) throw invalidParams("action is missing or unknown");
  // Required for the sub-flows nested in an oid4vci/oid4vp flow; a plain Core sign flow has no parent.
  if (p.parent_flow_id !== undefined && (typeof p.parent_flow_id !== "string" || p.parent_flow_id === "")) {
    throw invalidParams("parent_flow_id is malformed");
  }
  for (const k of STRING_MEMBERS) {
    if (p[k] !== undefined && typeof p[k] !== "string") throw invalidParams(`${k} is not a string`);
  }
  for (const k of OBJECT_MEMBERS) {
    if (p[k] !== undefined && !isObj(p[k])) throw invalidParams(`${k} is not an object`);
  }
  if (p.count !== undefined && (!Number.isInteger(p.count) || (p.count as number) < 1 || (p.count as number) > MAX_PROOF_COUNT)) {
    throw invalidParams(`count is not an integer from 1 to ${MAX_PROOF_COUNT}`);
  }
  if (p.deferred !== undefined && typeof p.deferred !== "boolean") throw invalidParams("deferred is not a boolean");
  if (p.selection_handle !== undefined && !isSelectionHandle(p.selection_handle)) throw invalidParams("selection_handle is malformed");
  if (p.credential_response_encryption !== undefined) {
    const c = p.credential_response_encryption;
    if (!isObj(c) || typeof c.alg !== "string" || typeof c.enc !== "string" || (c.required !== undefined && typeof c.required !== "boolean")) {
      throw invalidParams("credential_response_encryption is malformed");
    }
  }
  if (p.auxiliary_data_to_issuer !== undefined && (!Array.isArray(p.auxiliary_data_to_issuer) || !p.auxiliary_data_to_issuer.every(isObj))) {
    throw invalidParams("auxiliary_data_to_issuer is not an array of objects");
  }
  if (p.credentials_to_include !== undefined) {
    const c = p.credentials_to_include;
    if (!Array.isArray(c) || !c.every((e) => isObj(e) && Object.keys(e).length === 1 && typeof e.credential_query_id === "string" && e.credential_query_id !== "")) {
      throw invalidParams("credentials_to_include is not an array of {credential_query_id}");
    }
  }
  if (p.action === "sign_presentation" && (typeof p.nonce !== "string" || typeof p.audience !== "string")) {
    throw invalidParams("sign_presentation needs nonce and audience");
  }
  if (p.transaction_data !== undefined) {
    if (!Array.isArray(p.transaction_data)) throw invalidParams("transaction_data is not an array");
    for (const e of p.transaction_data) {
      if (!isObj(e)) throw invalidParams("transaction_data entry is not an object");
      // An orchestrator that predates `raw`: the wallet cannot bind to the transaction.
      if (typeof e.raw !== "string" || e.raw === "") throw transactionDataUnsupportedError();
      if (typeof e.type !== "string") throw invalidParams("transaction_data entry type is not a string");
      if (!Array.isArray(e.credential_ids) || !e.credential_ids.every((x) => typeof x === "string")) {
        throw invalidParams("transaction_data entry credential_ids is not an array of strings");
      }
      if (e.payload !== undefined && !isObj(e.payload)) throw invalidParams("transaction_data entry payload is not an object");
      if (e.transaction_data_hashes_alg !== undefined) {
        const a = e.transaction_data_hashes_alg;
        const ok = typeof a === "string" ? a !== "" : Array.isArray(a) && a.length > 0 && a.every((x) => typeof x === "string" && x !== "");
        if (!ok) throw invalidParams("transaction_data_hashes_alg is not a non-empty string or array of non-empty strings");
      }
      checkTransactionDataEntry(e as unknown as TransactionData);
    }
    if (p.transaction_data.length > 0 && p.action === "sign_presentation" && typeof p.response_mode !== "string") {
      throw invalidParams("response_mode is required with transaction_data");
    }
  }
  return { ...(p as unknown as SignSubFlowParams) };
}

// ---------------------------------------------------------------------------
// Answering a sub-flow
// ---------------------------------------------------------------------------

/** What the answer helpers need of a Peer. */
export type FlowNotifier = Pick<PeerContext, "notify">;

/**
 * A notifier bound to ONE flow generation: its sends fail, without sending, once
 * that flow ended (cancelled, completed, replaced under the same id), and never
 * retire another generation's record. Falls back to plain `notify` for a
 * PeerContext that cannot tell generations apart.
 */
export function boundNotifier(peer: PeerContext, flowId: string): FlowNotifier & { current(): boolean } {
  const generation = peer.flowGeneration?.(flowId);
  return {
    notify: (method, params) => (peer.notifyFlow ? peer.notifyFlow(generation, method, params) : peer.notify(method, params)),
    // Whether the flow this notifier was made for is still the active one.
    current: () => !peer.flowGeneration || (generation !== undefined && peer.flowGeneration(flowId) === generation),
  };
}

/**
 * Ends a sub-flow successfully (wmp.flow.complete). The result is checked first
 * (default: the completion rules of {@link validateCompletionResult}; for a
 * match flow pass {@link validateMatchResult}); a result that would be refused
 * by the orchestrator is never sent.
 */
export async function completeSubFlow(
  peer: FlowNotifier,
  wmp: Metadata,
  flowId: string,
  result: unknown,
  validate: (result: unknown) => void = (r) => validateCompletionResult(r),
): Promise<void> {
  validate(result);
  await peer.notify(Method.FlowComplete, { wmp: meta(wmp), flow_id: flowId, result });
}

/** Ends a sub-flow with wmp.flow.error (a failure, not a refusal). */
export async function failSubFlow(
  peer: FlowNotifier,
  wmp: Metadata,
  flowId: string,
  code: number,
  message: string,
  data?: unknown,
): Promise<void> {
  await peer.notify(Method.FlowError, { wmp: meta(wmp), flow_id: flowId, code, message, data });
}

/**
 * The wallet declines the sub-flow (the user said no, it does not trust the
 * verifier, a value the signature must bind is missing): wmp.flow.error -31006
 * with data {"reason": "rejected"}, the well-known reason of Core 6.2
 * (profile 3.2.6). Any other error is a failure, not a refusal.
 */
export async function rejectSubFlow(peer: FlowNotifier, wmp: Metadata, flowId: string, message = "declined"): Promise<void> {
  await failSubFlow(peer, wmp, flowId, ErrorCode.FlowError, message, { reason: "rejected" });
}

/**
 * The wallet will not process the sub-flow's transaction_data: wmp.flow.error
 * -31005 with data {"unsupported": "transaction_data"} (profile 2.3).
 */
export async function unsupportedTransactionData(peer: FlowNotifier, wmp: Metadata, flowId: string): Promise<void> {
  await failSubFlow(peer, wmp, flowId, ErrorCode.CapabilityNotSupported, "Capability not supported", transactionDataUnsupportedData());
}

function meta(wmp: Metadata): Metadata {
  return { version: wmp.version || VERSION, ...(wmp.session_id ? { session_id: wmp.session_id } : {}) };
}

/** A member that is really there: not undefined/null (which JSON drops or nulls) and not empty. */
function present(v: unknown): boolean {
  if (v === undefined || v === null) return false;
  if (typeof v === "string") return v !== "";
  if (Array.isArray(v)) return v.length > 0;
  if (typeof v === "object") return Object.keys(v as object).length > 0;
  return true;
}

/** Response modes in which the wallet encrypts the response (profile 7.7). */
const ENCRYPTED_RESPONSE_MODES = ["direct_post.jwt", "dc_api.jwt"];

/** The members a decrypt_credential_response result may carry: control members only. */
const DECRYPT_RESULT_MEMBERS = ["credential_count", "transaction_id", "interval", "error"];

/**
 * Checks the result of a sign sub-flow before it is sent: the completion rules
 * and, per action, what must never reach the orchestrator. A
 * decrypt_credential_response result carries control members only
 * (credential_count or transaction_id with an optional interval, or an error):
 * the decrypted credentials and their metadata stay in the wallet (profile
 * 3.1.5.1), so any other member, credentials and credential_metadata first,
 * refuses the result.
 */
export function validateSignResult(action: string, result: unknown, responseMode?: string): void {
  validateCompletionResult(result);
  const r = result as Record<string, unknown>;
  if (action === "sign_presentation") {
    // An encrypted response mode: the wallet builds and encrypts the response
    // itself and answers with response_jwe; a plaintext vp_token would reach the
    // orchestrator unprotected and no later refusal can undo that (profile 7.7).
    // A plaintext mode has no use for a JWE the orchestrator cannot read.
    const encrypted = responseMode !== undefined && ENCRYPTED_RESPONSE_MODES.includes(responseMode);
    if ("error" in r) {
      // An error result carries no presentation in any mode, and no response_jwe
      // (profile 7.7): it reports a refusal, there is nothing to encrypt. The
      // error itself must be real: undefined/null/empty would serialize to a
      // result that says nothing at all.
      if (!present(r.error)) throw new CompletionResultError("error is empty");
      if ("vp_token" in r || "response_jwe" in r) throw new CompletionResultError("an error result carries neither vp_token nor response_jwe");
    } else if (encrypted) {
      if ("vp_token" in r) throw new CompletionResultError("vp_token in an encrypted response mode; the response must be a response_jwe");
      if (!("response_jwe" in r)) throw new CompletionResultError("an encrypted response mode needs a response_jwe");
    } else {
      // A plaintext (or unspecified) mode answers with the VP token (profile
      // 3.2.5); a result without one would end the sub-flow with no presentation.
      if ("response_jwe" in r) throw new CompletionResultError("response_jwe in a response mode that is not encrypted");
      if (!present(r.vp_token)) throw new CompletionResultError("a successful sign_presentation result carries a vp_token");
    }
    return;
  }
  if (action !== "decrypt_credential_response") return;
  for (const k of Object.keys(r)) {
    if (!DECRYPT_RESULT_MEMBERS.includes(k)) throw new CompletionResultError("decryption result carries a member outside the control set");
  }
  if (!("credential_count" in r) && !("transaction_id" in r) && !("error" in r)) {
    throw new CompletionResultError("decryption result carries no credential_count, transaction_id or error");
  }
  if ("error" in r && !present(r.error)) throw new CompletionResultError("error is empty");
}

/** The sub-flow a wallet was asked to answer, with the means to answer it. A sub-flow ends once. */
export class SignFlow {
  private done = false;

  constructor(
    private peer: FlowNotifier,
    private wmp: Metadata,
    readonly flowId: string,
    readonly params: SignSubFlowParams,
  ) {}

  /** True once a terminal message (complete, reject, fail) was sent for this sub-flow. */
  get ended(): boolean {
    return this.done;
  }

  /**
   * Sends at most one terminal message. The sub-flow counts as ended from the
   * moment the send starts (a concurrent second terminal is refused); if the
   * message is not sent (a result that fails validation, a transport error) it
   * counts as not ended, so the caller can still answer another way.
   */
  private async terminal(send: () => Promise<void>): Promise<void> {
    if (this.done) throw new Error("sub-flow already ended");
    this.done = true;
    try {
      await send();
    } catch (err) {
      this.done = false;
      throw err;
    }
  }

  /** Completes with the sign result (e.g. `{ proof_jwt }`, `{ response_jwe }`). */
  complete(result: unknown): Promise<void> {
    return this.terminal(() =>
      completeSubFlow(this.peer, this.wmp, this.flowId, result, (r) => validateSignResult(this.params.action, r, this.params.response_mode)),
    );
  }

  /** Declines the sub-flow (-31006, reason rejected). */
  reject(message?: string): Promise<void> {
    return this.terminal(() => rejectSubFlow(this.peer, this.wmp, this.flowId, message));
  }

  /** Fails the sub-flow without refusing it. */
  fail(code: number, message: string, data?: unknown): Promise<void> {
    return this.terminal(() => failSubFlow(this.peer, this.wmp, this.flowId, code, message, data));
  }

  /** Cannot process the request's transaction_data (-31005). */
  unsupportedTransactionData(): Promise<void> {
    return this.terminal(() => unsupportedTransactionData(this.peer, this.wmp, this.flowId));
  }
}

// ---------------------------------------------------------------------------
// match flow (profile 3.3)
// ---------------------------------------------------------------------------

/** Params of a `match` flow.start. */
export interface MatchStartParams {
  parent_flow_id: string;
  /** The verifier's DCQL query as validated by the orchestrator. */
  dcql_query: { credentials?: { id: string; [m: string]: unknown }[]; [m: string]: unknown };
  client_metadata?: Record<string, unknown>;
  verified_request?: Record<string, unknown>;
}

/** The result of a match: the closed set of profile 3.3.2. */
export interface MatchResult {
  satisfiable: boolean;
  satisfiable_query_ids?: string[];
  selection_handle?: string;
  code?: "no_match" | "insufficient" | "error";
}

/** Validates the params of a match flow.start (-32602 when malformed). */
export function parseMatchStartParams(raw: unknown): MatchStartParams {
  if (!isObj(raw)) throw invalidParams("params is not an object");
  if (typeof raw.parent_flow_id !== "string" || raw.parent_flow_id === "") throw invalidParams("parent_flow_id is missing");
  if (!isObj(raw.dcql_query)) throw invalidParams("dcql_query is missing");
  for (const k of ["client_metadata", "verified_request"]) {
    if (raw[k] !== undefined && !isObj(raw[k])) throw invalidParams(`${k} is not an object`);
  }
  return { ...(raw as unknown as MatchStartParams) };
}
