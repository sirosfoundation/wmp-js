/**
 * Completion-result rules of the WMP OpenID4x profile (Sections 3.1.4, 3.1.5.1,
 * 3.3 and 7.7) — mirrors go-wmp/pkg/wmp/openid4x/completion.go and replay.go
 * (v0.11.0).
 *
 * A client MUST refuse a wmp.flow.complete whose result breaks these rules, and
 * MUST treat every member listed in `redacted_members` as unrecoverable. None of
 * the functions here reads or returns a member VALUE in an error: errors name
 * the member or rule only, so a refusal never echoes a secret.
 */

/** Largest credential_count a client may report from a decrypted response. */
export const MAX_ENCRYPTED_CREDENTIAL_COUNT = 256;
/** Largest response_jwe an orchestrator relays, in characters. */
export const MAX_RESPONSE_JWE_LEN = 4 << 20;

/**
 * credential_metadata members that carry a Secret Value and are never relayed
 * in a completion (OpenID4VCI Credential Auxiliary Data). Default for the
 * `secretMembers` argument of {@link validateCompletionResult}.
 */
export const DEFAULT_SECRET_MEMBERS: readonly string[] = Object.freeze(["auxiliary_data"]);

/**
 * The only result members a replayed wmp.flow.complete withholds, and the only
 * names `redacted_members` may list (Section 3.1.4): the OID4VCI refresh token
 * and the DPoP key it is bound to. Sorted.
 */
export const REPLAY_SECRET_MEMBERS: readonly string[] = Object.freeze([
  "dpop_jwk",
  "dpop_key_id",
  "refresh_token",
]);

const REDACTED_MEMBERS_KEY = "redacted_members";
const METHOD_FLOW_COMPLETE = "wmp.flow.complete";

/** Raised for every non-conforming completion or match result. */
export class CompletionResultError extends Error {
  constructor(message: string) {
    super(`non-conforming flow result: ${message}`);
    this.name = "CompletionResultError";
  }
}

type Obj = Record<string, unknown>;

function isObj(v: unknown): v is Obj {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function has(o: Obj, k: string): boolean {
  return Object.prototype.hasOwnProperty.call(o, k);
}

function fail(msg: string): never {
  throw new CompletionResultError(msg);
}

/**
 * Checks the `result` of a wmp.flow.complete (an oid4vci completion or a sign
 * sub-flow result). Throws {@link CompletionResultError} on the first
 * violation. Members it does not know are ignored (Core Section 9.5).
 *
 * The rules:
 * - credential_metadata is an object and carries none of `secretMembers`;
 * - credential_response_encrypted is a boolean; when true there is no
 *   credential_metadata and no credentials[].credential value;
 * - redacted_members is a non-empty array of distinct {@link REPLAY_SECRET_MEMBERS}
 *   names, and none of the members it lists is present in the same result;
 * - a decrypt_credential_response result has credential_count (1 to 256) or
 *   transaction_id, never both, and carries no credentials or
 *   credential_metadata; interval only accompanies transaction_id;
 * - a response_jwe is a compact JWE of five base64url segments (only the
 *   encrypted key may be empty), at most {@link MAX_RESPONSE_JWE_LEN} long, and
 *   never accompanies a vp_token.
 */
export function validateCompletionResult(
  result: unknown,
  secretMembers: readonly string[] = DEFAULT_SECRET_MEMBERS,
): void {
  if (!isObj(result)) fail("result is not an object");
  const encrypted = validateEncryptedFlag(result);
  validateCredentialMetadata(result, encrypted, secretMembers);
  if (encrypted) validateNoCredentialValues(result);
  validateRedactedMembers(result);
  validateDecryptResult(result);
  validateResponseJWE(result);
}

function validateEncryptedFlag(m: Obj): boolean {
  if (!has(m, "credential_response_encrypted")) return false;
  const v = m.credential_response_encrypted;
  if (typeof v !== "boolean") fail("credential_response_encrypted is not a boolean");
  return v;
}

function validateCredentialMetadata(m: Obj, encrypted: boolean, secretMembers: readonly string[]): void {
  if (!has(m, "credential_metadata")) return;
  const meta = m.credential_metadata;
  if (!isObj(meta)) fail("credential_metadata is not an object");
  for (const secret of secretMembers) {
    if (has(meta, secret)) fail(`credential_metadata carries ${secret}, which is never relayed`);
  }
  if (encrypted) fail("credential_metadata present although credential_response_encrypted is true");
}

function validateNoCredentialValues(m: Obj): void {
  if (!has(m, "credentials")) return;
  const creds = m.credentials;
  if (!Array.isArray(creds)) fail("credentials is not an array of objects");
  creds.forEach((c, i) => {
    if (!isObj(c)) fail(`credentials[${i}] is not an object`);
    if (has(c, "credential")) {
      fail(`credentials[${i}] carries a credential value although credential_response_encrypted is true`);
    }
  });
}

function validateRedactedMembers(m: Obj): void {
  if (!has(m, REDACTED_MEMBERS_KEY)) return;
  const names = m[REDACTED_MEMBERS_KEY];
  if (!Array.isArray(names) || names.length === 0 || names.some((n) => typeof n !== "string")) {
    fail("redacted_members is not a non-empty array of strings");
  }
  const seen = new Set<string>();
  for (const n of names as string[]) {
    if (!REPLAY_SECRET_MEMBERS.includes(n)) fail("redacted_members lists a member that is not a replay secret member");
    if (seen.has(n)) fail("redacted_members lists a member twice");
    seen.add(n);
    // A member cannot be both withheld and delivered: a client that read the
    // delivered value would contradict the marker it was told to honour.
    if (has(m, n)) fail("redacted_members lists a member that the result also carries");
  }
}

function validateDecryptResult(m: Obj): void {
  const hasCount = has(m, "credential_count");
  const hasTx = has(m, "transaction_id");
  if (hasCount && hasTx) fail("both transaction_id and credential_count");
  if (!hasCount && !hasTx) {
    validateAbsentInterval(m);
    return;
  }
  for (const k of ["credentials", "credential_metadata"]) {
    if (has(m, k)) fail(`decryption result carries ${k}`);
  }
  if (hasCount) {
    const n = m.credential_count;
    if (!Number.isInteger(n) || (n as number) < 1 || (n as number) > MAX_ENCRYPTED_CREDENTIAL_COUNT) {
      fail(`credential_count is not an integer from 1 to ${MAX_ENCRYPTED_CREDENTIAL_COUNT}`);
    }
    // An interval belongs only to a deferred (transaction_id) result.
    validateAbsentInterval(m);
    return;
  }
  const tx = m.transaction_id;
  if (typeof tx !== "string" || tx === "") fail("transaction_id is not a non-empty string");
  if (has(m, "interval")) {
    const iv = m.interval;
    if (!Number.isInteger(iv) || (iv as number) < 0) fail("interval is not a non-negative integer");
  }
}

function validateAbsentInterval(m: Obj): void {
  if (has(m, "interval")) fail("interval without transaction_id");
}

function validateResponseJWE(m: Obj): void {
  if (!has(m, "response_jwe")) return;
  if (has(m, "vp_token")) fail("response_jwe together with vp_token");
  const jwe = m.response_jwe;
  if (typeof jwe !== "string" || jwe === "" || jwe.length > MAX_RESPONSE_JWE_LEN) {
    fail(`response_jwe is not a non-empty string of at most ${MAX_RESPONSE_JWE_LEN} bytes`);
  }
  const parts = jwe.split(".");
  if (parts.length !== 5) fail("response_jwe is not a compact JWE of five segments");
  parts.forEach((p, i) => {
    if (p === "" && i !== 1) fail(`response_jwe segment ${i + 1} is empty`);
    if (!/^[A-Za-z0-9_-]*$/.test(p)) fail(`response_jwe segment ${i + 1} is not base64url`);
  });
}

// ---------------------------------------------------------------------------
// match flow result (Section 3.3)
// ---------------------------------------------------------------------------

const MATCH_MEMBERS = ["satisfiable", "satisfiable_query_ids", "selection_handle", "code"];
const MATCH_CODES = ["no_match", "insufficient", "error"];
// 22 or more base64url characters, no padding, canonical length (4n, 4n+2, 4n+3).
const MATCH_HANDLE = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$/;

/**
 * Checks the `result` of a wmp.flow.complete for a flow of type match
 * (Section 3.3.2). The result is a closed set: nothing but satisfiable,
 * satisfiable_query_ids, selection_handle and code may be present, so no claim,
 * disclosure, credential, identifier or free text can ride along (Section
 * 3.3.3). The caller selects this check by the flow type it recorded for the
 * flow_id, never by members of the result.
 *
 * @param queryIds the `id` values of the verifier's DCQL query when known; every
 *   satisfiable_query_ids element must then be one of them.
 */
export function validateMatchResult(result: unknown, queryIds?: readonly string[]): void {
  if (!isObj(result)) fail("match result is not an object");
  for (const k of Object.keys(result)) {
    if (!MATCH_MEMBERS.includes(k)) fail("match result carries a member outside the closed set");
  }
  if (typeof result.satisfiable !== "boolean") fail("satisfiable is not a boolean");
  if (result.satisfiable) {
    if (has(result, "code")) fail("code present although satisfiable is true");
  } else if (!has(result, "code")) {
    fail("code absent although satisfiable is false");
  }
  if (has(result, "code") && !MATCH_CODES.includes(result.code as string)) {
    fail("code is not one of no_match, insufficient, error");
  }
  if (has(result, "satisfiable_query_ids")) {
    const ids = result.satisfiable_query_ids;
    if (!Array.isArray(ids) || ids.some((x) => typeof x !== "string")) fail("satisfiable_query_ids is not an array of strings");
    const seen = new Set<string>();
    for (const id of ids as string[]) {
      if (seen.has(id)) fail("satisfiable_query_ids repeats an element");
      seen.add(id);
      if (queryIds && !queryIds.includes(id)) fail("satisfiable_query_ids has an element that is not an id of the query");
    }
  }
  if (has(result, "selection_handle")) {
    const h = result.selection_handle;
    if (typeof h !== "string" || h.length < 22 || !MATCH_HANDLE.test(h)) fail("selection_handle is not a base64url string of at least 22 characters");
  }
}

/** The `id` of each credential query of a DCQL query (for {@link validateMatchResult}). */
export function dcqlQueryIds(query: unknown): string[] {
  const creds = isObj(query) ? query.credentials : undefined;
  return Array.isArray(creds) ? creds.filter((c): c is { id: string } => isObj(c) && typeof c.id === "string").map((c) => c.id) : [];
}

/**
 * The secret members a replayed completion reports as withheld, or [] when it
 * reports none. A client MUST treat each as unrecoverable: it did not
 * necessarily not exist, and no value may be fabricated or substituted for it.
 * Call it on a result that passed {@link validateCompletionResult}.
 */
export function redactedMembers(result: unknown): string[] {
  if (!isObj(result) || !Array.isArray(result[REDACTED_MEMBERS_KEY])) return [];
  return (result[REDACTED_MEMBERS_KEY] as unknown[]).filter(
    (n): n is string => typeof n === "string" && REPLAY_SECRET_MEMBERS.includes(n),
  );
}

// ---------------------------------------------------------------------------
// splitReplaySecrets (Section 3.1.4.2) — mirrors replay.go
// ---------------------------------------------------------------------------

export interface ReplaySplit {
  /** False when the message mentions a secret member but cannot be parsed as such a completion: do not retain it. */
  ok: boolean;
  /** The form safe to retain for replay. Empty when !ok. */
  replay: string;
  /** The live form, set only when the replay form differs from the input. */
  live?: string;
}

/**
 * Separates a serialised outbound JSON-RPC message into the form safe to retain
 * for replay and the live form (Section 3.1.4). For a wmp.flow.complete whose
 * result carries any of {@link REPLAY_SECRET_MEMBERS}, replay is the
 * notification with exactly those members removed and `"redacted_members":
 * [<names withheld, sorted>]` added to the result, and live is the input
 * unchanged. Every other member, credential_metadata included, is preserved. For
 * any other message, or a completion with nothing to withhold, replay is the
 * input and live is absent.
 *
 * ok is false when the message mentions a secret member but is not a
 * well-formed completion, has a duplicate member name (a reader would see
 * either value), has a name that differs from a structural name only in letter
 * case, or its result already carries redacted_members: the caller must not
 * retain it. The replay copy of a conforming input satisfies
 * {@link validateCompletionResult}.
 */
export function splitReplaySecrets(data: string | Uint8Array): ReplaySplit {
  const text = typeof data === "string" ? data : new TextDecoder("utf-8", { fatal: false }).decode(data);
  if (!mayNeedRedaction(text)) return { ok: true, replay: text };
  const env = scanObject(text, ["method", "params"]);
  if (!env) return REFUSED;
  const rawMethod = env.get("method");
  if (rawMethod === undefined) return { ok: true, replay: text }; // a response carries no completion
  let method: unknown;
  try {
    method = JSON.parse(rawMethod);
  } catch {
    return REFUSED;
  }
  if (typeof method !== "string") return REFUSED;
  if (method !== METHOD_FLOW_COMPLETE) return { ok: true, replay: text };

  const params = scanObject(env.get("params") ?? "", ["result"]);
  if (!params) return REFUSED;
  const rawResult = params.get("result");
  if (rawResult === undefined) return { ok: true, replay: text }; // result is optional
  const result = scanObject(rawResult, [REDACTED_MEMBERS_KEY, ...REPLAY_SECRET_MEMBERS]);
  if (!result) return REFUSED;
  if (result.has(REDACTED_MEMBERS_KEY)) return REFUSED;
  const withheld: string[] = [];
  for (const k of REPLAY_SECRET_MEMBERS) {
    if (result.has(k)) {
      withheld.push(k);
      result.delete(k);
    }
  }
  if (withheld.length === 0) return { ok: true, replay: text };
  result.set(REDACTED_MEMBERS_KEY, JSON.stringify(withheld));
  params.set("result", assemble(result));
  env.set("params", assemble(params));
  return { ok: true, replay: assemble(env), live: text };
}

const REFUSED: ReplaySplit = { ok: false, replay: "" };

function assemble(m: Map<string, string>): string {
  return "{" + [...m].map(([k, v]) => `${JSON.stringify(k)}:${v}`).join(",") + "}";
}

/**
 * True when text could carry a secret member or a redacted_members member. A
 * JSON key may be spelled with escapes ("refresh_token") or with non-ASCII
 * letters that case-fold to ASCII (U+017F, U+212A), so any escape or non-ASCII
 * character counts; redacted_members counts because a live completion never
 * carries it.
 */
function mayNeedRedaction(text: string): boolean {
  const lower = text.toLowerCase();
  // eslint-disable-next-line no-control-regex
  if (/[^\u0000-\u007f]/.test(text) || lower.includes("\\u") || lower.includes(`"${REDACTED_MEMBERS_KEY}"`)) {
    return true;
  }
  return REPLAY_SECRET_MEMBERS.some((k) => lower.includes(`"${k}"`));
}

function foldCase(s: string): string {
  return s.replace(/ſ/g, "s").replace(/K/g, "k").toLowerCase();
}

/**
 * Splits a JSON text that is exactly one object into its members, in order,
 * keyed by the DECODED name, each value the verbatim source text. Returns
 * undefined for anything but exactly one object whose names are distinct after
 * decoding, or that has a name equal to one of `exact` only up to letter case.
 */
function scanObject(text: string, exact: readonly string[]): Map<string, string> | undefined {
  let i = 0;
  const n = text.length;
  const ws = (): void => {
    while (i < n && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  // Returns the end index (exclusive) of the string literal starting at i.
  const stringEnd = (start: number): number => {
    let j = start + 1;
    while (j < n) {
      const c = text[j];
      if (c === "\\") j += 2;
      else if (c === '"') return j + 1;
      else j++;
    }
    return -1;
  };
  // Returns the end index of the JSON value starting at i, or -1.
  const valueEnd = (start: number): number => {
    const c = text[start];
    if (c === '"') return stringEnd(start);
    if (c === "{" || c === "[") {
      let depth = 0;
      let j = start;
      while (j < n) {
        const d = text[j];
        if (d === '"') {
          const e = stringEnd(j);
          if (e < 0) return -1;
          j = e;
          continue;
        }
        if (d === "{" || d === "[") depth++;
        else if (d === "}" || d === "]") {
          depth--;
          if (depth === 0) return j + 1;
        }
        j++;
      }
      return -1;
    }
    let j = start;
    while (j < n && !/[,}\]\s]/.test(text[j])) j++;
    return j > start ? j : -1;
  };

  ws();
  if (text[i] !== "{") return undefined;
  i++;
  const members = new Map<string, string>();
  ws();
  if (text[i] === "}") {
    i++;
  } else {
    for (;;) {
      ws();
      if (text[i] !== '"') return undefined;
      const ke = stringEnd(i);
      if (ke < 0) return undefined;
      let key: string;
      try {
        key = JSON.parse(text.slice(i, ke)) as string;
      } catch {
        return undefined;
      }
      i = ke;
      ws();
      if (text[i] !== ":") return undefined;
      i++;
      ws();
      const ve = valueEnd(i);
      if (ve < 0) return undefined;
      const raw = text.slice(i, ve);
      try {
        JSON.parse(raw); // the value must itself be well-formed JSON
      } catch {
        return undefined;
      }
      if (members.has(key)) return undefined;
      const folded = foldCase(key);
      if (exact.some((e) => key !== e && folded === e)) return undefined;
      members.set(key, raw);
      i = ve;
      ws();
      if (text[i] === ",") {
        i++;
        continue;
      }
      if (text[i] === "}") {
        i++;
        break;
      }
      return undefined;
    }
  }
  ws();
  return i === n ? members : undefined;
}
