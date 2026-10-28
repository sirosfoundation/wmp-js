/**
 * The `select_credentials` consent action (WMP OpenID4x profile 3.2.3.1,
 * schema/methods/select-credentials-params.json).
 *
 * The params are a closed set: `consent` and `selections` of
 * `{query_id, selection_handle}`. Nothing that identifies a credential, a claim
 * or the user can ride along, so the orchestrator learns only that the user
 * consented and for which of the verifier's own query ids. Unknown members are
 * REFUSED here, unlike elsewhere in WMP (Core 9.5): ignoring a member would
 * still have received it. Errors never echo a value.
 */

import { getRandomValues } from "./random.js";
import type { ConsentAction, CredentialSelection } from "./openid4x.js";

export class ActionParamsError extends Error {
  constructor(message: string) {
    super(`non-conforming action params: ${message}`);
    this.name = "ActionParamsError";
  }
}

// 22 or more base64url characters, no padding, a length a base64url encoding can have (4n, 4n+2, 4n+3).
const HANDLE_FORM = /^(?:[A-Za-z0-9_-]{4})*(?:[A-Za-z0-9_-]{2,3})?$/;
// No ASCII or Unicode whitespace, no C0/C1 controls, no zero-width or byte-order-mark characters.
const FORBIDDEN_IN_QUERY_ID: readonly (readonly [number, number])[] = [
  [0x0000, 0x0020], // C0 controls and the space
  [0x007f, 0x00a0], // DEL, C1 controls and the no-break space
  [0x1680, 0x1680],
  [0x2000, 0x200b], // spaces and zero-width characters
  [0x2028, 0x202f],
  [0x205f, 0x2060],
  [0x3000, 0x3000],
  [0xfeff, 0xfeff], // byte-order mark
];

/** True for a well-formed selection handle (profile 3.2.3.1, 3.3.2). */
export function isSelectionHandle(h: unknown): h is string {
  return typeof h === "string" && h.length >= 22 && HANDLE_FORM.test(h);
}

/** True for a well-formed query_id (1 to 256 code points, the form of the schema pattern). */
export function isQueryId(q: unknown): q is string {
  if (typeof q !== "string") return false;
  let n = 0;
  for (const ch of q) {
    const cp = ch.codePointAt(0)!;
    if (FORBIDDEN_IN_QUERY_ID.some(([lo, hi]) => cp >= lo && cp <= hi)) return false;
    n++;
  }
  return n >= 1 && n <= 256;
}

/**
 * A fresh selection handle: 128 random bits as 22 base64url characters
 * (profile 3.3.2). It MUST NOT be derived from a credential, its identifier,
 * its content or the user, and MUST NOT be reused in another flow: mint one per
 * flow and keep it.
 */
export function newSelectionHandle(): string {
  const bytes = getRandomValues(16);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export interface SelectCredentialsContext {
  /** The ids of the verifier's credential queries (or input descriptors). Each query_id must be one. */
  queryIds?: readonly string[];
  /** The handle of the match result for this request, when it carried one: every selection must equal it. */
  matchHandle?: string;
}

function isObj(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function refuse(msg: string): never {
  throw new ActionParamsError(msg);
}

/**
 * Checks the `params` of a select_credentials action. Throws
 * {@link ActionParamsError} on the first violation: a member outside the closed
 * set, a wrong type, a malformed query_id or handle, a handle that differs
 * between elements (or from `matchHandle`), a query_id that is repeated (or not
 * in `queryIds`), selections present when consent is false, or absent/empty when
 * it is true.
 */
export function validateSelectCredentialsParams(params: unknown, ctx: SelectCredentialsContext = {}): ConsentAction {
  if (!isObj(params)) refuse("params is not an object");
  for (const k of Object.keys(params)) {
    if (k !== "consent" && k !== "selections") refuse("params carries a member outside the closed set");
  }
  if (typeof params.consent !== "boolean") refuse("consent is not a boolean");
  const consent = params.consent;
  const sel = params.selections;
  if (sel !== undefined && !Array.isArray(sel)) refuse("selections is not an array");
  if (!consent) {
    if (sel !== undefined && sel.length > 0) refuse("selections present although consent is false");
    return { consent: false, ...(sel !== undefined ? { selections: [] } : {}) };
  }
  if (sel === undefined || sel.length === 0) refuse("selections absent or empty although consent is true");
  const seen = new Set<string>();
  let handle: string | undefined;
  const out: CredentialSelection[] = [];
  sel.forEach((s: unknown, i: number) => {
    if (!isObj(s)) refuse(`selections[${i}] is not an object`);
    for (const k of Object.keys(s)) {
      if (k !== "query_id" && k !== "selection_handle") refuse(`selections[${i}] carries a member outside the closed set`);
    }
    if (!isQueryId(s.query_id)) refuse(`selections[${i}].query_id is missing or malformed`);
    if (!isSelectionHandle(s.selection_handle)) refuse(`selections[${i}].selection_handle is missing or malformed`);
    if (seen.has(s.query_id)) refuse("query_id repeated");
    seen.add(s.query_id);
    if (ctx.queryIds && !ctx.queryIds.includes(s.query_id)) refuse(`selections[${i}].query_id is not an id of the request`);
    if (handle !== undefined && s.selection_handle !== handle) refuse("selection_handle differs between elements");
    handle = s.selection_handle;
    out.push({ query_id: s.query_id, selection_handle: s.selection_handle });
  });
  if (ctx.matchHandle !== undefined && handle !== ctx.matchHandle) refuse("selection_handle differs from the match result's handle");
  return { consent: true, selections: out };
}

/**
 * Builds select_credentials params after validating them: the user declined
 * (`consent: false`) or consents to the given query ids, all under one handle
 * (the match result's, or {@link newSelectionHandle}).
 */
export function buildSelectCredentials(
  decision: { consent: false } | { consent: true; queryIds: readonly string[]; selectionHandle: string },
  ctx: SelectCredentialsContext = {},
): ConsentAction {
  const params = decision.consent
    ? { consent: true, selections: decision.queryIds.map((q) => ({ query_id: q, selection_handle: decision.selectionHandle })) }
    : { consent: false };
  return validateSelectCredentialsParams(params, ctx);
}
