// Per-request proof for HTTPS sessions (WMP Core section 4.4.8).
//
// A compact JWS, modelled on DPoP (RFC 9449), that binds one HTTP request to
// one WMP session and proves possession of the key the session was
// authenticated with. It is sent as "Authorization: DPoP <proof>".

/** The "typ" header parameter of a proof. */
export const REQUEST_PROOF_TYPE = "wmp-proof+jwt";
/** The Authorization scheme a proof is sent under. */
export const REQUEST_PROOF_SCHEME = "DPoP";
/** Default clock-skew tolerance in seconds (WMP Core section 8.5.1). */
export const REQUEST_PROOF_SKEW_SECONDS = 30;

export type RequestProofAlgorithm = "ES256" | "ES384" | "ES512" | "EdDSA";

const ALGORITHMS: Record<
  RequestProofAlgorithm,
  { importParams: EcKeyImportParams | Algorithm; verifyParams: EcdsaParams | Algorithm; size: number }
> = {
  ES256: { importParams: { name: "ECDSA", namedCurve: "P-256" }, verifyParams: { name: "ECDSA", hash: "SHA-256" }, size: 64 },
  ES384: { importParams: { name: "ECDSA", namedCurve: "P-384" }, verifyParams: { name: "ECDSA", hash: "SHA-384" }, size: 96 },
  ES512: { importParams: { name: "ECDSA", namedCurve: "P-521" }, verifyParams: { name: "ECDSA", hash: "SHA-512" }, size: 132 },
  EdDSA: { importParams: { name: "Ed25519" }, verifyParams: { name: "Ed25519" }, size: 64 },
};

const CURVE_ALGORITHMS: Record<string, RequestProofAlgorithm> = {
  "P-256": "ES256",
  "P-384": "ES384",
  "P-521": "ES512",
};

/** A proof that does not pass verification. A server answers the request with 401. */
export class RequestProofError extends Error {
  constructor(reason: string) {
    super(`invalid request proof: ${reason}`);
    this.name = "RequestProofError";
  }
}

/** Signs the JWS signing input of a proof. */
export interface RequestProofSigner {
  /** The JWS "alg" of the signatures `sign` makes. */
  alg: RequestProofAlgorithm;
  /** Returns the JWS signature over `input` (for ECDSA the fixed-width R||S form). */
  sign(input: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

/** The payload of a proof. */
export interface RequestProofClaims {
  /** The HTTP request method. */
  htm: string;
  /** The HTTP request URI without query and fragment. */
  htu: string;
  /** Issuance time, unix seconds. */
  iat: number;
  /** Unique identifier of this proof. */
  jti: string;
  /** The WMP session the proof is bound to. */
  sid: string;
  /** base64url SHA-256 of the access token the request also carries (RFC 9449 section 4.2). */
  ath?: string;
}

export interface CreateRequestProofOptions {
  signer: RequestProofSigner;
  /**
   * The certificate chain of the key, leaf first: DER bytes or base64 DER.
   * Set it for sessions authenticated with x5c.
   */
  x5c?: Array<string | Uint8Array>;
  /** The DID Document key id. Set it, instead of `x5c`, for signed_challenge sessions. */
  kid?: string;
  /** The HTTP method of the request. */
  method: string;
  /** The absolute request URL. Its query and fragment are left out of `htu`. */
  url: string;
  /** The WMP session of the request. */
  sessionId: string;
  /** The bearer token the request also carries; its hash becomes `ath`. */
  accessToken?: string;
  /** Current time in unix seconds. Default: the system clock. */
  now?: () => number;
}

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function toBase64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCodePoint(b);
  return btoa(s);
}

function fromBase64(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.codePointAt(i)!;
  return out;
}

function toBase64Url(bytes: Uint8Array): string {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromBase64Url(s: string, what: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s) || s.length % 4 === 1) throw new RequestProofError(`${what} encoding`);
  const out = fromBase64(s.replaceAll("-", "+").replaceAll("_", "/"));
  // Canonical only: the unused bits of the last character are zero.
  if (toBase64Url(out) !== s) throw new RequestProofError(`${what} encoding`);
  return out;
}

async function tokenHash(token: string): Promise<string> {
  return toBase64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(token))));
}

/**
 * The `htu` form of a URL: scheme and host in lower case, the default port
 * removed. With `strip` the query and fragment are dropped; without it a URL
 * that carries either is refused.
 */
function normalizeUrl(raw: string, strip: boolean): string {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("not an absolute URL");
  }
  if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username !== "" || u.password !== "") {
    throw new Error("not an absolute http(s) URL");
  }
  if (!strip && (raw.includes("?") || raw.includes("#"))) {
    throw new Error("htu carries a query or fragment");
  }
  return `${u.protocol}//${u.host}${u.pathname}`;
}

/** The JCS (RFC 8785) serialisation of the claims. */
function canonicalClaims(c: RequestProofClaims): string {
  const members: Array<[string, string | number]> = [];
  if (c.ath !== undefined) members.push(["ath", c.ath]);
  members.push(["htm", c.htm], ["htu", c.htu], ["iat", c.iat], ["jti", c.jti], ["sid", c.sid]);
  const body = members.map(([k, v]) => JSON.stringify(k) + ":" + JSON.stringify(v)).join(",");
  return `{${body}}`;
}

/** A signer for a WebCrypto private key (ECDSA P-256, P-384, P-521 or Ed25519). */
export function webCryptoProofSigner(key: CryptoKey): RequestProofSigner {
  const alg = algorithmOfKey(key);
  if (alg === undefined) throw new Error("unsupported key for a request proof");
  const params = ALGORITHMS[alg].verifyParams;
  return {
    alg,
    sign: async (input) => new Uint8Array(await crypto.subtle.sign(params, key, input as BufferSource)),
  };
}

function algorithmOfKey(key: CryptoKey): RequestProofAlgorithm | undefined {
  if (key.algorithm.name === "Ed25519") return "EdDSA";
  if (key.algorithm.name === "ECDSA") return CURVE_ALGORITHMS[(key.algorithm as EcKeyAlgorithm).namedCurve];
  return undefined;
}

/** Makes a compact JWS proof for one request. */
export async function createRequestProof(opts: CreateRequestProofOptions): Promise<string> {
  const hasChain = opts.x5c !== undefined && opts.x5c.length > 0;
  const hasKid = opts.kid !== undefined && opts.kid !== "";
  if (hasChain === hasKid) throw new Error("exactly one of x5c and kid is required");
  if (!opts.method || !opts.sessionId) throw new Error("method and session id are required");
  if (!(opts.signer.alg in ALGORITHMS)) throw new Error(`unsupported algorithm ${String(opts.signer.alg)}`);

  const header: Record<string, unknown> = { alg: opts.signer.alg, typ: REQUEST_PROOF_TYPE };
  if (hasKid) header.kid = opts.kid;
  else header.x5c = opts.x5c!.map((c) => (typeof c === "string" ? c : toBase64(c)));

  const claims: RequestProofClaims = {
    htm: opts.method,
    htu: normalizeUrl(opts.url, true),
    iat: opts.now ? Math.floor(opts.now()) : Math.floor(Date.now() / 1000),
    jti: toBase64Url(crypto.getRandomValues(new Uint8Array(16))),
    sid: opts.sessionId,
  };
  if (opts.accessToken) claims.ath = await tokenHash(opts.accessToken);

  const input = `${toBase64Url(encoder.encode(JSON.stringify(header)))}.${toBase64Url(encoder.encode(canonicalClaims(claims)))}`;
  const sig = await opts.signer.sign(encoder.encode(input));
  return `${input}.${toBase64Url(sig)}`;
}

/** The proof in an Authorization header value, or undefined when it does not use the DPoP scheme. */
export function requestProofFromHeader(authorization: string | null | undefined): string | undefined {
  const m = /^dpop +(\S+) *$/i.exec(authorization ?? "");
  return m ? m[1] : undefined;
}

/** What a proof must be bound to. */
export interface RequestProofExpectation {
  /** The method of the request the proof arrived on. */
  method: string;
  /** The URL the request was sent to, as the client saw it. */
  url: string;
  /**
   * The session the request names. When it is undefined the `sid` claim is not
   * compared and the caller MUST compare the returned `claims.sid` itself.
   */
  sessionId?: string;
  /**
   * The bearer token the request also carries. When set, the proof must carry
   * its hash in `ath`; when not, a proof with an `ath` is refused.
   */
  accessToken?: string;
}

export interface VerifyRequestProofOptions {
  /**
   * Validates an `x5c` chain (DER, leaf first) against the trust anchors and
   * throws when it does not hold. A proof with a chain is refused when this
   * is not set.
   */
  verifyChain?: (chain: Uint8Array[]) => void | Promise<void>;
  /**
   * Returns the public key of a `kid` (a DID Document key id), or undefined.
   * A proof with a kid is refused when this is not set.
   */
  resolveKey?: (kid: string) => CryptoKey | undefined | Promise<CryptoKey | undefined>;
  /** Accepted algorithms. Default: ES256, ES384, ES512, EdDSA. */
  algorithms?: RequestProofAlgorithm[];
  /** Clock-skew tolerance on `iat`, seconds. Default 30. */
  skewSeconds?: number;
  /** Detects a proof presented twice. */
  replay?: RequestProofReplayCache;
  /** Current time in unix seconds. Default: the system clock. */
  now?: () => number;
}

/** Remembers proof identifiers for as long as a proof stays inside the skew window. */
export interface RequestProofReplayCache {
  /** Records `key` until `expires` (unix seconds) and reports whether it was already recorded. */
  seen(key: string, expires: number): boolean | Promise<boolean>;
}

/** A verified proof. */
export interface VerifiedRequestProof {
  alg: RequestProofAlgorithm;
  claims: RequestProofClaims;
  /** The validated `x5c` chain as DER, leaf first. Undefined for a `kid` proof. */
  chain?: Uint8Array[];
  /** The `kid` header. Undefined for an `x5c` proof. */
  kid?: string;
  /** The public key that verified the signature. */
  key: CryptoKey;
}

function parseObject(bytes: Uint8Array, what: string): Record<string, unknown> {
  let v: unknown;
  try {
    v = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new RequestProofError(`${what} is not JSON`);
  }
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new RequestProofError(`${what} is not a JSON object`);
  return v as Record<string, unknown>;
}

function stringMember(o: Record<string, unknown>, name: string): string {
  const v = Object.hasOwn(o, name) ? o[name] : undefined;
  if (typeof v !== "string" || v === "") throw new RequestProofError(`${name} is not a non-empty string`);
  return v;
}

// --- minimal DER reading: the subjectPublicKeyInfo of a certificate ---------

function readTlv(der: Uint8Array, at: number): { tag: number; start: number; end: number } {
  if (at + 2 > der.length) throw new Error("truncated");
  const tag = der[at];
  let len = der[at + 1];
  let start = at + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > der.length) throw new Error("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + der[start + i];
    start += n;
  }
  if (start + len > der.length) throw new Error("truncated");
  return { tag, start, end: start + len };
}

/** Returns the DER subjectPublicKeyInfo of an X.509 certificate. */
function certificateSpki(der: Uint8Array): Uint8Array {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) throw new Error("not a certificate");
  const tbs = readTlv(der, cert.start);
  if (tbs.tag !== 0x30) throw new Error("not a certificate");
  let at = tbs.start;
  let field = readTlv(der, at);
  if (field.tag === 0xa0) {
    // the explicit version
    at = field.end;
    field = readTlv(der, at);
  }
  // serialNumber, signature, issuer, validity, subject
  for (let i = 0; i < 5; i++) {
    at = field.end;
    if (at >= tbs.end) throw new Error("not a certificate");
    field = readTlv(der, at);
  }
  if (field.tag !== 0x30 || field.end > tbs.end) throw new Error("not a certificate");
  return der.slice(at, field.end);
}

function parseChain(v: unknown): Uint8Array[] {
  if (!Array.isArray(v) || v.length === 0) throw new RequestProofError("x5c is not a non-empty array");
  return v.map((e) => {
    if (typeof e !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(e) || e.length % 4 !== 0) {
      throw new RequestProofError("x5c entry is not base64 DER");
    }
    return fromBase64(e);
  });
}

interface ProofKey {
  key: CryptoKey;
  chain?: Uint8Array[];
  kid?: string;
}

/** Checks the protected header and returns its algorithm. */
function headerAlgorithm(header: Record<string, unknown>, opts: VerifyRequestProofOptions): RequestProofAlgorithm {
  const alg = stringMember(header, "alg") as RequestProofAlgorithm;
  if (stringMember(header, "typ") !== REQUEST_PROOF_TYPE) throw new RequestProofError(`typ is not ${REQUEST_PROOF_TYPE}`);
  const accepted = opts.algorithms ?? (Object.keys(ALGORITHMS) as RequestProofAlgorithm[]);
  if (!Object.hasOwn(ALGORITHMS, alg) || !accepted.includes(alg)) throw new RequestProofError(`algorithm ${alg} is not accepted`);
  if (Object.hasOwn(header, "crit")) throw new RequestProofError("crit is not supported");
  return alg;
}

async function chainKey(header: Record<string, unknown>, alg: RequestProofAlgorithm, opts: VerifyRequestProofOptions): Promise<ProofKey> {
  const chain = parseChain(header.x5c);
  if (!opts.verifyChain) throw new RequestProofError("x5c proofs are not accepted");
  try {
    const spki = certificateSpki(chain[0]) as BufferSource;
    return { chain, key: await crypto.subtle.importKey("spki", spki, ALGORITHMS[alg].importParams, true, ["verify"]) };
  } catch {
    throw new RequestProofError(`leaf key does not fit algorithm ${alg}`);
  }
}

async function resolvedKey(header: Record<string, unknown>, alg: RequestProofAlgorithm, opts: VerifyRequestProofOptions): Promise<ProofKey> {
  const kid = stringMember(header, "kid");
  if (!opts.resolveKey) throw new RequestProofError("kid proofs are not accepted");
  let key: CryptoKey | undefined;
  try {
    key = await opts.resolveKey(kid);
  } catch {
    key = undefined;
  }
  if (!key) throw new RequestProofError("kid does not resolve");
  if (algorithmOfKey(key) !== alg) throw new RequestProofError(`key does not fit algorithm ${alg}`);
  return { kid, key };
}

/** The key the header names: the leaf of its x5c chain, or the key of its kid. */
function proofKey(header: Record<string, unknown>, alg: RequestProofAlgorithm, opts: VerifyRequestProofOptions): Promise<ProofKey> {
  const hasChain = Object.hasOwn(header, "x5c");
  if (hasChain === Object.hasOwn(header, "kid")) throw new RequestProofError("exactly one of x5c and kid is required");
  return hasChain ? chainKey(header, alg, opts) : resolvedKey(header, alg, opts);
}

async function checkSignature(alg: RequestProofAlgorithm, key: CryptoKey, input: string, sig: Uint8Array): Promise<void> {
  if (sig.length !== ALGORITHMS[alg].size) throw new RequestProofError("signature length");
  let valid = false;
  try {
    valid = await crypto.subtle.verify(ALGORITHMS[alg].verifyParams, key, sig as BufferSource, encoder.encode(input) as BufferSource);
  } catch {
    valid = false;
  }
  if (!valid) throw new RequestProofError("signature");
}

function parseClaims(payload: Record<string, unknown>): RequestProofClaims {
  const iat = Object.hasOwn(payload, "iat") ? payload.iat : undefined;
  if (typeof iat !== "number" || !Number.isSafeInteger(iat)) throw new RequestProofError("iat is not an integer");
  const claims: RequestProofClaims = {
    htm: stringMember(payload, "htm"),
    htu: stringMember(payload, "htu"),
    iat,
    jti: stringMember(payload, "jti"),
    sid: stringMember(payload, "sid"),
  };
  if (Object.hasOwn(payload, "ath")) claims.ath = stringMember(payload, "ath");
  return claims;
}

/** Checks that the claims name the session, the request and the access token. */
async function checkBinding(claims: RequestProofClaims, expect: RequestProofExpectation): Promise<void> {
  if (expect.sessionId !== undefined && claims.sid !== expect.sessionId) {
    throw new RequestProofError("sid does not name this session");
  }
  if (claims.htm !== expect.method) throw new RequestProofError("htm does not match the request");
  let claimed: string | undefined;
  try {
    claimed = normalizeUrl(claims.htu, false);
  } catch {
    claimed = undefined;
  }
  if (claimed === undefined || claimed !== normalizeUrl(expect.url, true)) {
    throw new RequestProofError("htu does not match the request");
  }
  const wantHash = expect.accessToken ? await tokenHash(expect.accessToken) : undefined;
  if (claims.ath !== wantHash) throw new RequestProofError("ath does not match the access token");
}

/**
 * Verifies a compact JWS proof (WMP Core section 4.4.8, verification steps 1
 * to 5) and throws RequestProofError when it does not pass. The caller still
 * matches the returned identity (the leaf certificate's SAN, or the key id) to
 * the principal the session was created under.
 */
export async function verifyRequestProof(
  proof: string,
  expect: RequestProofExpectation,
  opts: VerifyRequestProofOptions,
): Promise<VerifiedRequestProof> {
  const parts = proof.split(".");
  if (parts.length !== 3) throw new RequestProofError("not a three-segment compact JWS");
  const header = parseObject(fromBase64Url(parts[0], "header"), "header");
  const payloadBytes = fromBase64Url(parts[1], "payload");
  const sig = fromBase64Url(parts[2], "signature");

  const alg = headerAlgorithm(header, opts);
  const { key, chain, kid } = await proofKey(header, alg, opts);
  await checkSignature(alg, key, `${parts[0]}.${parts[1]}`, sig);
  const claims = parseClaims(parseObject(payloadBytes, "payload"));
  await checkBinding(claims, expect);

  const now = opts.now ? opts.now() : Date.now() / 1000;
  const skew = opts.skewSeconds !== undefined && opts.skewSeconds > 0 ? opts.skewSeconds : REQUEST_PROOF_SKEW_SECONDS;
  if (claims.iat < now - skew || claims.iat > now + skew) {
    throw new RequestProofError("iat outside the clock-skew tolerance");
  }
  if (chain) {
    try {
      await opts.verifyChain!(chain);
    } catch (err) {
      throw new RequestProofError(`certificate chain: ${err instanceof Error ? err.message : String(err)}`);
    }
  }
  // Last, so that only an otherwise valid proof consumes its jti.
  if (opts.replay && (await opts.replay.seen(`${claims.sid}\u0000${claims.jti}`, claims.iat + 2 * skew))) {
    throw new RequestProofError("jti was already used");
  }
  return { alg, claims, chain, kid, key };
}

/** An in-process replay cache. A deployment with several instances needs a shared one. */
export class MemoryRequestProofReplayCache implements RequestProofReplayCache {
  private readonly entries = new Map<string, number>();
  /** When expired entries are next removed: a lookup does not pay for the whole cache. */
  private sweepAt = 0;
  constructor(private readonly now: () => number = () => Date.now() / 1000) {}

  seen(key: string, expires: number): boolean {
    const now = this.now();
    if (now >= this.sweepAt) {
      for (const [k, exp] of this.entries) if (exp <= now) this.entries.delete(k);
      this.sweepAt = now + 1;
    }
    const known = this.entries.get(key);
    if (known !== undefined && known > now) return true;
    this.entries.set(key, expires);
    return false;
  }
}
