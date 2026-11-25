// Non-repudiation signatures (WMP Core section 5.4).
//
// A detached JWS (RFC 7515 Appendix F) with an unencoded payload (RFC 7797)
// over the JCS (RFC 8785) form of a message's content object, made with the
// sender's long-lived key. Its value is `<header>..<signature>`; for ECDSA the
// signature is the fixed-width R||S form of JWS, not DER.

import {
  ALGORITHMS,
  algorithmOfKey,
  certificateSpki,
  fromBase64,
  toBase64,
  toBase64Url,
  type RequestProofAlgorithm,
  type RequestProofSigner,
} from "./proof.js";

/** A content signature that does not verify. A receiver answers the message with -31010. */
export class ContentSignatureError extends Error {
  constructor(reason: string) {
    super(`invalid content signature: ${reason}`);
    this.name = "ContentSignatureError";
  }
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function canonicalMember(key: string, value: unknown, path: string): string | undefined {
  // As in JSON.stringify, a member without a value is not part of the object.
  if (value === undefined) return undefined;
  return `${JSON.stringify(key)}:${canonicalValue(value, `${path}.${key}`)}`;
}

function canonicalValue(value: unknown, path: string): string {
  if (value === null || typeof value === "boolean") return String(value);
  if (typeof value === "string") {
    if (LONE_SURROGATE.test(value)) throw new TypeError(`${path}: a string with a lone surrogate has no canonical form`);
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError(`${path}: ${value} has no canonical form`);
    // RFC 8785 section 3.2.2.3 serialises numbers as ECMAScript does.
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((v, i) => canonicalValue(v, `${path}[${i}]`)).join(",")}]`;
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Object.prototype && proto !== null) throw new TypeError(`${path}: not a plain JSON object`);
    const o = value as Record<string, unknown>;
    // The default sort compares UTF-16 code units, the order RFC 8785 section 3.2.3 requires.
    const members = Object.keys(o)
      .sort()
      .map((k) => canonicalMember(k, o[k], path))
      .filter((m) => m !== undefined);
    return `{${members.join(",")}}`;
  }
  throw new TypeError(`${path}: a ${typeof value} has no canonical form`);
}

/** The JSON Canonicalization Scheme (RFC 8785) form of a JSON value. */
export function canonicalize(value: unknown): string {
  return canonicalValue(value, "$");
}

/**
 * The content object of a request (WMP Core section 5.4): its `params` without
 * the `wmp` member. For an encrypted message that is `{ciphertext}`, plus
 * `plaintext_hash` when the sender commits to the plaintext.
 */
export function contentObject(params: Record<string, unknown>): Record<string, unknown> {
  const { wmp: _wmp, ...content } = params;
  return content;
}

export interface SignContentOptions {
  signer: RequestProofSigner;
  /** The certificate chain of the signing key, leaf first: DER bytes or base64 DER. */
  x5c?: Array<string | Uint8Array>;
  /** The key identifier: a DID URL, an X.509 subject key identifier or a JWK thumbprint. */
  kid?: string;
}

function isSet(kid: string | undefined): kid is string {
  return kid !== undefined && kid !== "";
}

/**
 * Signs a content object and returns the `wmp.signature` value. The header
 * names the key by `x5c`, by `kid`, or by both.
 */
export async function signContent(content: unknown, opts: SignContentOptions): Promise<string> {
  const hasChain = opts.x5c !== undefined && opts.x5c.length > 0;
  if (!hasChain && !isSet(opts.kid)) throw new Error("one of x5c and kid is required");
  if (!Object.hasOwn(ALGORITHMS, opts.signer.alg)) throw new Error(`unsupported algorithm ${String(opts.signer.alg)}`);

  const header: Record<string, unknown> = { alg: opts.signer.alg, b64: false, crit: ["b64"] };
  if (isSet(opts.kid)) header.kid = opts.kid;
  if (hasChain) header.x5c = opts.x5c!.map((c) => (typeof c === "string" ? c : toBase64(c)));

  const protectedHeader = toBase64Url(encoder.encode(JSON.stringify(header)));
  const sig = await opts.signer.sign(encoder.encode(`${protectedHeader}.${canonicalize(content)}`));
  return `${protectedHeader}..${toBase64Url(sig)}`;
}

export interface VerifyContentSignatureOptions {
  /**
   * Validates an `x5c` chain (DER, leaf first) against the trust anchors and
   * throws when it does not hold. A signature with a chain is refused when
   * this is not set.
   */
  verifyChain?: (chain: Uint8Array[]) => void | Promise<void>;
  /**
   * Returns the public key of a `kid`, or undefined. A signature that names
   * its key only by `kid` is refused when this is not set.
   */
  resolveKey?: (kid: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** Accepted algorithms. Default: ES256, ES384, ES512, EdDSA. */
  algorithms?: RequestProofAlgorithm[];
}

/** A verified content signature. */
export interface VerifiedContentSignature {
  alg: RequestProofAlgorithm;
  /** The validated `x5c` chain as DER, leaf first, when the header carries one. */
  chain?: Uint8Array[];
  /** The `kid` header, when present. */
  kid?: string;
  /** The public key that verified the signature. */
  key: CryptoKey;
}

function decodeBase64Url(s: string, what: string): Uint8Array {
  if (s === "" || !/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) throw new ContentSignatureError(`${what} encoding`);
  const out = fromBase64(s.replaceAll("-", "+").replaceAll("_", "/"));
  if (toBase64Url(out) !== s) throw new ContentSignatureError(`${what} encoding`);
  return out;
}

function parseHeader(segment: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(decoder.decode(decodeBase64Url(segment, "header")));
  } catch (err) {
    if (err instanceof ContentSignatureError) throw err;
    throw new ContentSignatureError("header is not JSON");
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new ContentSignatureError("header is not a JSON object");
  return v as Record<string, unknown>;
}

function own(o: Record<string, unknown>, name: string): unknown {
  return Object.hasOwn(o, name) ? o[name] : undefined;
}

function headerAlgorithm(header: Record<string, unknown>, opts: VerifyContentSignatureOptions): RequestProofAlgorithm {
  const alg = own(header, "alg");
  const accepted = opts.algorithms ?? (Object.keys(ALGORITHMS) as RequestProofAlgorithm[]);
  if (typeof alg !== "string" || !Object.hasOwn(ALGORITHMS, alg) || !accepted.includes(alg as RequestProofAlgorithm)) {
    throw new ContentSignatureError(`algorithm ${String(alg)} is not accepted`);
  }
  if (own(header, "b64") !== false) throw new ContentSignatureError("b64 is not false");
  const crit = own(header, "crit");
  // "b64" must be critical and is the only critical parameter understood here.
  if (!Array.isArray(crit) || crit.length !== 1 || crit[0] !== "b64") throw new ContentSignatureError('crit is not ["b64"]');
  return alg as RequestProofAlgorithm;
}

function headerChain(header: Record<string, unknown>): Uint8Array[] | undefined {
  if (!Object.hasOwn(header, "x5c")) return undefined;
  const v = header.x5c;
  if (!Array.isArray(v) || v.length === 0) throw new ContentSignatureError("x5c is not a non-empty array");
  return v.map((e) => {
    if (typeof e !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(e) || e.length % 4 !== 0) {
      throw new ContentSignatureError("x5c entry is not base64 DER");
    }
    return fromBase64(e);
  });
}

function headerKid(header: Record<string, unknown>): string | undefined {
  if (!Object.hasOwn(header, "kid")) return undefined;
  const kid = header.kid;
  if (typeof kid !== "string" || kid === "") throw new ContentSignatureError("kid is not a non-empty string");
  return kid;
}

async function leafKey(chain: Uint8Array[], alg: RequestProofAlgorithm, opts: VerifyContentSignatureOptions): Promise<CryptoKey> {
  if (!opts.verifyChain) throw new ContentSignatureError("x5c signatures are not accepted");
  try {
    const spki = certificateSpki(chain[0]) as BufferSource;
    return await crypto.subtle.importKey("spki", spki, ALGORITHMS[alg].importParams, true, ["verify"]);
  } catch {
    throw new ContentSignatureError(`leaf key does not fit algorithm ${alg}`);
  }
}

async function kidKey(kid: string | undefined, alg: RequestProofAlgorithm, opts: VerifyContentSignatureOptions): Promise<CryptoKey> {
  if (kid === undefined) throw new ContentSignatureError("the header names no key");
  if (!opts.resolveKey) throw new ContentSignatureError("kid signatures are not accepted");
  let key: CryptoKey | undefined;
  try {
    key = await opts.resolveKey(kid);
  } catch {
    key = undefined;
  }
  if (!key) throw new ContentSignatureError("kid does not resolve");
  if (algorithmOfKey(key) !== alg) throw new ContentSignatureError(`key does not fit algorithm ${alg}`);
  return key;
}

/**
 * Verifies a `wmp.signature` value over a content object (WMP Core section
 * 5.4) and throws ContentSignatureError when it does not verify. The key is
 * the leaf of the header's `x5c` chain when there is one, otherwise the key
 * of its `kid`. The caller still matches the returned identity to the sender.
 */
export async function verifyContentSignature(
  signature: string,
  content: unknown,
  opts: VerifyContentSignatureOptions,
): Promise<VerifiedContentSignature> {
  if (typeof signature !== "string") throw new ContentSignatureError("not a string");
  const parts = signature.split(".");
  if (parts.length !== 3 || parts[1] !== "") throw new ContentSignatureError("not a detached compact JWS");
  const header = parseHeader(parts[0]);
  const sig = decodeBase64Url(parts[2], "signature");

  const alg = headerAlgorithm(header, opts);
  const chain = headerChain(header);
  const kid = headerKid(header);
  const key = chain ? await leafKey(chain, alg, opts) : await kidKey(kid, alg, opts);

  if (sig.length !== ALGORITHMS[alg].size) throw new ContentSignatureError("signature length");
  let canonical: string;
  try {
    canonical = canonicalize(content);
  } catch {
    throw new ContentSignatureError("the content has no canonical form");
  }
  let valid = false;
  try {
    const input = encoder.encode(`${parts[0]}.${canonical}`);
    valid = await crypto.subtle.verify(ALGORITHMS[alg].verifyParams, key, sig as BufferSource, input as BufferSource);
  } catch {
    valid = false;
  }
  if (!valid) throw new ContentSignatureError("signature");

  if (chain) {
    try {
      await opts.verifyChain!(chain);
    } catch (err) {
      throw new ContentSignatureError(`certificate chain: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  return { alg, chain, kid, key };
}
