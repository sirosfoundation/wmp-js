// The QERDS sender profile: a registered electronic delivery as one call.
//
//   session create (mTLS, or the per-request proof of WMP Core section 4.4.8)
//   -> resolve each recipient and a fresh MLS KeyPackage for it
//   -> an MLS group whose leaf carries the sender's certificate chain
//   -> wmp.mls.group.create (GroupInfo and the Welcome)
//   -> wmp.message.deliver: the ciphertext as the only content field, the
//      section 5.4 signature and the section 5.6 x509_chain identity assertion
//   -> the evidence repository, polled until the delivery is confirmed
//
// One certificate chain serves every role: the per-request proof, the content
// signature, the MLS leaf credential and the identity assertion (and, outside
// this module, the TLS client certificate of the injected fetch).

import {
  createApplicationMessage,
  createCommit,
  createGroup,
  createGroupInfoWithExternalPubAndRatchetTree,
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  zeroOutUint8Array,
  type CiphersuiteName,
  type ClientState,
  type MLSMessage,
  type Proposal,
} from "ts-mls";

import { WMPError } from "./jsonrpc.js";
import { CipherSuiteP256AES128GCM, CipherSuiteX25519AES128GCM, MLSMethod } from "./mls.js";
import { createRequestProof, fromBase64, toBase64, toBase64Url, type RequestProofSigner } from "./proof.js";
import { canonicalize, signContent } from "./signature.js";
import { ErrorCode, Method, VERSION, type Capabilities, type IdentityAssertion, type SecurityMode } from "./types.js";

/** The step of the flow a QerdsError belongs to. */
export type QerdsStep = "config" | "session" | "resolve" | "group" | "deliver" | "evidence";

/** A QERDS send that did not complete. `cause` carries the WMPError of a refused request. */
export class QerdsError extends Error {
  constructor(
    readonly step: QerdsStep,
    reason: string,
    options?: { cause?: unknown },
  ) {
    super(`qerds ${step}: ${reason}`, options);
    this.name = "QerdsError";
  }
}

/** The sender's credential: one certificate chain and the signer of its leaf key. */
export interface QerdsCredential {
  /** The certificate chain, leaf first: DER bytes or base64 DER. */
  chain: Array<string | Uint8Array>;
  /** Signs with the leaf's private key (see webCryptoProofSigner). */
  signer: RequestProofSigner;
  /** A `kid` for the content signature header, next to its `x5c`. */
  kid?: string;
}

/** An MLS KeyPackage a recipient published (WMP MLS section 2.3). */
export interface QerdsKeyPackage {
  id?: string;
  cipher_suite: number;
  /** base64url MLSMessage carrying the KeyPackage. */
  key_package: string;
}

/** An MLS group with the recipients added, ready to send in. */
export interface QerdsGroup {
  /** base64url group id. */
  groupId: string;
  cipherSuite: number;
  /** base64url MLSMessage carrying the GroupInfo of the epoch the recipients join. */
  groupInfo: string;
  /** base64url MLSMessage carrying the Welcome, per recipient. */
  welcomes: Record<string, string>;
  /** Encrypts an application message: a base64url MLSMessage and the epoch it belongs to. */
  encrypt(plaintext: Uint8Array): Promise<{ ciphertext: string; epoch: number }>;
}

/** The MLS engine of the profile. */
export interface QerdsGroupProvider {
  /**
   * Creates a group whose own leaf carries `certificates` as an X.509
   * credential and adds one member per entry of `keyPackages`.
   */
  createGroup(opts: {
    cipherSuite: number;
    /** DER certificates, leaf first. */
    certificates: Uint8Array[];
    /** One KeyPackage per recipient. */
    keyPackages: Record<string, QerdsKeyPackage>;
  }): Promise<QerdsGroup>;
}

/** An evidence record of the repository (WMP Evidence section 6.2). */
export interface QerdsEvidenceRecord {
  evidence_id: string;
  event_type: string;
  event_time?: string;
  original_message_id?: string;
  original_content_hash?: { algorithm: string; value: string };
  signed_evidence?: string;
  timestamp_token?: string;
  [member: string]: unknown;
}

export interface QerdsEvidenceOptions {
  /** Poll the evidence repository after the deliver. Default: true. */
  poll?: boolean;
  /** Event types that end the poll. Default: delivery_confirmed and the terminal failures. */
  until?: string[];
  /** How long to poll. Default: 90 000 ms. */
  timeoutMs?: number;
  /** Pause between polls. Default: 5 000 ms. */
  intervalMs?: number;
  /** The repository URL. Default: the negotiated `evidence.repository`, else `<endpoint>/evidence`. */
  repository?: string;
}

export interface SendQerdsOptions {
  /** The WMP HTTPS endpoint of the ERDS: the URL JSON-RPC requests are POSTed to. */
  endpoint: string;
  /** The sender's participant identifier. */
  sender: string;
  /** The recipients' participant identifiers. */
  recipients: string[];
  credential: QerdsCredential;
  /**
   * How requests are authenticated. "mtls": the injected `fetch` presents the
   * client certificate. "dpop": each request carries a per-request proof made
   * with the credential. Default: "mtls".
   */
  auth?: "mtls" | "dpop";
  /** The ERDS' participant identifier. Default: `x509:san:dns:<host of endpoint>`. */
  responder?: string;
  message: {
    /** The message body. */
    body: unknown;
    /** Default: application/json. */
    contentType?: string;
    /** The JSON-RPC id of the deliver, which evidence refers to. Default: a fresh unique id. */
    id?: string;
  };
  /** Identity assertions of the deliver. Default: one `x509_chain` assertion with the credential's chain. */
  identityAssertions?: IdentityAssertion[];
  /** Commit to the plaintext with `plaintext_hash` (WMP Core section 5.2.1). Default: false. */
  plaintextHash?: boolean;
  /** Capabilities offered at session creation. Default: messaging, offline, resolve and evidence. */
  capabilities?: Capabilities;
  /** Default: `{mode: "mls", cipher_suites: [1, 2]}`. */
  security?: SecurityMode;
  /** Session lifetime in seconds. Default: 3600. */
  ttl?: number;
  evidence?: QerdsEvidenceOptions;
  /** The MLS engine. Default: ts-mls. */
  mls?: QerdsGroupProvider;
  /** The HTTPS client. For "mtls" it presents the client certificate. Default: the global fetch. */
  fetch?: typeof globalThis.fetch;
}

export interface SendQerdsResult {
  session: { id: string; security?: SecurityMode; capabilities?: Capabilities };
  group: { id: string; cipherSuite: number; epoch: number };
  /**
   * What was sent. Keep `content` and `signature` with `plaintext` for as
   * long as the evidence: together they show what the evidence attests to.
   */
  message: {
    id: string;
    /** The outer content object: `{ciphertext}`, plus `plaintext_hash` when committed. */
    content: Record<string, unknown>;
    /** The `wmp.signature` value over `content`. */
    signature: string;
    /** The plaintext content object that was encrypted. */
    plaintext: Record<string, unknown>;
  };
  /** The evidence records of this message, as last read. */
  evidence: QerdsEvidenceRecord[];
  /** An event type of `evidence.until` was reached. */
  confirmed: boolean;
}

const DEFAULT_EVENT_TYPES = [
  "submission_accepted",
  "relay_accepted",
  "relay_forwarded",
  "delivery_attempted",
  "delivery_confirmed",
  "delivery_failed",
  "retrieval_confirmed",
  "acceptance_confirmed",
];

const DEFAULT_UNTIL = ["delivery_confirmed", "delivery_failed", "submission_rejected"];

const encoder = new TextEncoder();

function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

function uniqueId(prefix: string): string {
  return `${prefix}-${crypto.randomUUID()}`;
}

function timestamp(): string {
  return new Date().toISOString().replace(/\.\d+Z$/, "Z");
}

function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(s) || s.length % 4 === 1) throw new Error("not base64url");
  return fromBase64(s.replaceAll("-", "+").replaceAll("_", "/"));
}

function derChain(chain: Array<string | Uint8Array>): Uint8Array[] {
  return chain.map((c) => (typeof c === "string" ? fromBase64(c) : c));
}

// ---------------------------------------------------------------------------
// The default MLS engine
// ---------------------------------------------------------------------------

const SUITE_NAMES: Record<number, CiphersuiteName> = {
  [CipherSuiteX25519AES128GCM]: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  [CipherSuiteP256AES128GCM]: "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
};

function addProposal(keyPackage: QerdsKeyPackage, recipient: string): Proposal {
  const decoded = decodeMlsMessage(fromBase64Url(keyPackage.key_package), 0);
  const msg = decoded?.[0];
  if (msg?.wireformat !== "mls_key_package") throw new Error(`the KeyPackage of ${recipient} is not an MLS KeyPackage message`);
  return { proposalType: "add", add: { keyPackage: msg.keyPackage } };
}

/** The ts-mls engine: a new group per call, the recipients added in its first commit. */
export function tsMlsQerdsGroups(): QerdsGroupProvider {
  return {
    async createGroup({ cipherSuite, certificates, keyPackages }) {
      const name = SUITE_NAMES[cipherSuite];
      if (!name) throw new Error(`unsupported cipher suite ${cipherSuite}`);
      const impl = await getCiphersuiteImpl(getCiphersuiteFromName(name));
      const own = await generateKeyPackage(
        { credentialType: "x509", certificates },
        defaultCapabilities(),
        defaultLifetime,
        [],
        impl,
      );
      const groupId = crypto.getRandomValues(new Uint8Array(16));
      const created = await createGroup(groupId, own.publicPackage, own.privatePackage, [], impl);

      const recipients = Object.keys(keyPackages);
      const commit = await createCommit(
        { state: created, cipherSuite: impl, pskIndex: emptyPskIndex },
        { extraProposals: recipients.map((r) => addProposal(keyPackages[r], r)), ratchetTreeExtension: true },
      );
      commit.consumed.forEach(zeroOutUint8Array);
      if (!commit.welcome) throw new Error("the commit produced no Welcome");
      let state: ClientState = commit.newState;

      const welcome = toBase64Url(
        encodeMlsMessage({ version: "mls10", wireformat: "mls_welcome", welcome: commit.welcome } as MLSMessage),
      );
      const info = await createGroupInfoWithExternalPubAndRatchetTree(state, [], impl);
      const groupInfo = toBase64Url(
        encodeMlsMessage({ version: "mls10", wireformat: "mls_group_info", groupInfo: info } as MLSMessage),
      );

      return {
        groupId: toBase64Url(groupId),
        cipherSuite,
        groupInfo,
        // One Welcome carries the secrets of every member the commit added.
        welcomes: Object.fromEntries(recipients.map((r) => [r, welcome])),
        async encrypt(plaintext) {
          // The epoch the message is encrypted in: the one the recipients join.
          const epoch = Number(state.groupContext.epoch);
          const out = await createApplicationMessage(state, plaintext, impl);
          state = out.newState;
          out.consumed.forEach(zeroOutUint8Array);
          const ciphertext = toBase64Url(
            encodeMlsMessage({
              version: "mls10",
              wireformat: "mls_private_message",
              privateMessage: out.privateMessage,
            } as MLSMessage),
          );
          return { ciphertext, epoch };
        },
      };
    },
  };
}

// ---------------------------------------------------------------------------
// The HTTPS client of one send
// ---------------------------------------------------------------------------

class QerdsClient {
  readonly endpoint: string;
  readonly x5c: string[];
  private readonly fetchFn: typeof globalThis.fetch;
  private readonly proofs: boolean;
  sessionId?: string;

  constructor(private readonly opts: SendQerdsOptions) {
    this.endpoint = opts.endpoint;
    this.x5c = opts.credential.chain.map((c) => (typeof c === "string" ? c : toBase64(c)));
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
    this.proofs = opts.auth === "dpop";
  }

  /** The `wmp` metadata of a request in the session. */
  meta(extra?: Record<string, unknown>): Record<string, unknown> {
    const wmp: Record<string, unknown> = { version: VERSION };
    if (this.sessionId !== undefined) wmp.session_id = this.sessionId;
    return { ...wmp, sender: this.opts.sender, timestamp: timestamp(), ...extra };
  }

  private async headers(method: string, url: string, base: Record<string, string>): Promise<Record<string, string>> {
    const headers = { ...base };
    if (this.sessionId !== undefined) headers["Wmp-Session-Id"] = this.sessionId;
    if (this.proofs) {
      // A fresh proof per request; the create's proof names no session.
      const proof = await createRequestProof({
        signer: this.opts.credential.signer,
        x5c: this.x5c,
        method,
        url,
        sessionId: this.sessionId,
      });
      headers.Authorization = `DPoP ${proof}`;
    }
    return headers;
  }

  /** One JSON-RPC request; a JSON-RPC error is thrown as a WMPError. */
  async call(method: string, params: Record<string, unknown>, id = uniqueId("req")): Promise<Record<string, unknown>> {
    const resp = await this.fetchFn(this.endpoint, {
      method: "POST",
      headers: await this.headers("POST", this.endpoint, { "Content-Type": "application/json", Accept: "application/json" }),
      body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
    });
    let answer: unknown;
    try {
      answer = JSON.parse(await resp.text());
    } catch {
      answer = undefined;
    }
    if (!isObject(answer)) throw new Error(`${method}: HTTP ${resp.status} without a JSON-RPC response`);
    if (isObject(answer.error)) {
      const { code, message, data } = answer.error;
      throw new WMPError(typeof code === "number" ? code : ErrorCode.InternalError, typeof message === "string" ? message : method, data);
    }
    if (!resp.ok) throw new Error(`${method}: HTTP ${resp.status}`);
    if (answer.id !== id || !isObject(answer.result)) throw new Error(`${method}: not the response to request ${id}`);
    return answer.result;
  }

  /** One page of the evidence repository. */
  async evidencePage(url: URL): Promise<Record<string, unknown>> {
    const resp = await this.fetchFn(url.toString(), {
      method: "GET",
      headers: await this.headers("GET", url.toString(), { Accept: "application/json" }),
    });
    if (!resp.ok) throw new Error(`evidence repository: HTTP ${resp.status}`);
    const page: unknown = await resp.json();
    if (!isObject(page)) throw new Error("evidence repository: not a JSON object");
    return page;
  }
}

async function step<T>(name: QerdsStep, what: string, run: () => Promise<T>): Promise<T> {
  try {
    return await run();
  } catch (err) {
    if (err instanceof QerdsError) throw err;
    throw new QerdsError(name, `${what}: ${err instanceof Error ? err.message : String(err)}`, { cause: err });
  }
}

// ---------------------------------------------------------------------------
// The steps
// ---------------------------------------------------------------------------

function checkOptions(opts: SendQerdsOptions): void {
  const fail = (reason: string): never => {
    throw new QerdsError("config", reason);
  };
  let url: URL | undefined;
  try {
    url = new URL(opts.endpoint);
  } catch {
    url = undefined;
  }
  if (url?.protocol !== "https:" && url?.protocol !== "http:") fail("endpoint is not an absolute http(s) URL");
  if (!opts.sender) fail("sender is required");
  if (!Array.isArray(opts.recipients) || opts.recipients.length === 0) fail("at least one recipient is required");
  if (opts.recipients.some((r) => typeof r !== "string" || r === "")) fail("a recipient is not a non-empty string");
  if (new Set(opts.recipients).size !== opts.recipients.length) fail("a recipient is named twice");
  if (!Array.isArray(opts.credential?.chain) || opts.credential.chain.length === 0) fail("credential.chain is empty");
  if (typeof opts.credential.signer?.sign !== "function") fail("credential.signer is required");
  if (opts.auth !== undefined && opts.auth !== "mtls" && opts.auth !== "dpop") fail(`auth ${String(opts.auth)} is not mtls or dpop`);
  if (!isObject(opts.message) || opts.message.body === undefined) fail("message.body is required");
}

function defaultCapabilitiesOffered(): Capabilities {
  return {
    messaging: { max_size: 65536 },
    offline: { max_queued: 1000, ttl: 2592000, status_notifications: true },
    resolve: { supported_types: ["mls_key_packages", "participant"] },
    evidence: { event_types: DEFAULT_EVENT_TYPES },
  } as Capabilities;
}

async function createSession(client: QerdsClient, opts: SendQerdsOptions): Promise<SendQerdsResult["session"]> {
  const responder = opts.responder ?? `x509:san:dns:${new URL(opts.endpoint).hostname}`;
  const result = await client.call(Method.SessionCreate, {
    wmp: client.meta(),
    participants: [responder],
    auth: { type: opts.auth ?? "mtls" },
    capabilities_offered: opts.capabilities ?? defaultCapabilitiesOffered(),
    security: opts.security ?? { mode: "mls", cipher_suites: [CipherSuiteX25519AES128GCM, CipherSuiteP256AES128GCM] },
    ttl: opts.ttl ?? 3600,
  });
  const id = isObject(result.wmp) ? result.wmp.session_id : undefined;
  if (typeof id !== "string" || id === "") throw new Error("the response names no session");
  client.sessionId = id;
  return {
    id,
    security: result.security as SecurityMode | undefined,
    capabilities: result.capabilities as Capabilities | undefined,
  };
}

/** The document a wmp.resolve answered: its `metadata` member, or the result itself. */
function resolved(result: Record<string, unknown>): Record<string, unknown> {
  return isObject(result.metadata) ? result.metadata : result;
}

async function resolveRecipient(client: QerdsClient, recipient: string): Promise<QerdsKeyPackage[]> {
  const participant = resolved(
    await client.call(Method.Resolve, { wmp: client.meta(), type: "participant", uri: recipient }),
  );
  if (participant.resolved !== true) throw new Error(`${recipient} does not resolve`);
  if (participant.qerds_capable !== true) throw new Error(`${recipient} is not QERDS-capable`);
  // KeyPackages are single-use (RFC 9420 section 10): resolved fresh for this group.
  const doc = resolved(await client.call(Method.Resolve, { wmp: client.meta(), type: "mls_key_packages", uri: recipient }));
  const list = doc.key_packages;
  if (!Array.isArray(list) || list.length === 0) throw new Error(`${recipient} has no KeyPackage`);
  return list.map((kp) => {
    if (!isObject(kp) || typeof kp.key_package !== "string" || kp.key_package === "" || !Number.isInteger(kp.cipher_suite)) {
      throw new Error(`a KeyPackage of ${recipient} is malformed`);
    }
    return kp as unknown as QerdsKeyPackage;
  });
}

/** The cipher suites the session negotiated, when it names any. */
function acceptedSuites(security: SecurityMode | undefined): number[] | undefined {
  if (Array.isArray(security?.cipher_suites) && security.cipher_suites.length > 0) return security.cipher_suites;
  return Number.isInteger(security?.cipher_suite) ? [security!.cipher_suite!] : undefined;
}

/** The cipher suite every recipient has a KeyPackage for, and that KeyPackage per recipient. */
function selectKeyPackages(
  published: Record<string, QerdsKeyPackage[]>,
  accepted: number[] | undefined,
): { cipherSuite: number; keyPackages: Record<string, QerdsKeyPackage> } {
  const recipients = Object.keys(published);
  // The first recipient's order of preference decides among the common suites.
  for (const candidate of published[recipients[0]]) {
    const suite = candidate.cipher_suite;
    if (accepted && !accepted.includes(suite)) continue;
    const picked = recipients.map((r) => published[r].find((kp) => kp.cipher_suite === suite));
    if (picked.every((kp) => kp !== undefined)) {
      return { cipherSuite: suite, keyPackages: Object.fromEntries(recipients.map((r, i) => [r, picked[i]!])) };
    }
  }
  throw new Error("the recipients share no cipher suite the session accepts");
}

async function plaintextCommitment(plaintext: Record<string, unknown>): Promise<{ algorithm: string; value: string }> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(canonicalize(plaintext)));
  return { algorithm: "sha-256", value: toBase64Url(new Uint8Array(digest)) };
}

async function deliver(
  client: QerdsClient,
  opts: SendQerdsOptions,
  group: QerdsGroup,
): Promise<{ message: SendQerdsResult["message"]; epoch: number }> {
  // The recipients, content type and body travel inside the ciphertext only:
  // a `to` next to `ciphertext` would be read as a plaintext message.
  const plaintext: Record<string, unknown> = {
    to: [...opts.recipients],
    content_type: opts.message.contentType ?? "application/json",
    body: opts.message.body,
  };
  const content: Record<string, unknown> = {};
  if (opts.plaintextHash) {
    plaintext.salt = toBase64Url(crypto.getRandomValues(new Uint8Array(16)));
    content.plaintext_hash = await plaintextCommitment(plaintext);
  }
  const { ciphertext, epoch } = await group.encrypt(encoder.encode(canonicalize(plaintext)));
  content.ciphertext = ciphertext;

  const signature = await signContent(content, {
    signer: opts.credential.signer,
    x5c: client.x5c,
    kid: opts.credential.kid,
  });
  const id = opts.message.id ?? uniqueId("msg");
  await client.call(
    Method.MessageDeliver,
    {
      wmp: client.meta({
        encrypted: true,
        epoch,
        signature,
        identity_assertions: opts.identityAssertions ?? [{ type: "x509_chain", x5c: client.x5c }],
      }),
      ...content,
    },
    id,
  );
  return { message: { id, content, signature, plaintext }, epoch };
}

function repositoryUrl(opts: SendQerdsOptions, session: SendQerdsResult["session"]): string {
  if (opts.evidence?.repository) return opts.evidence.repository;
  const negotiated = (session.capabilities as { evidence?: { repository?: unknown } } | undefined)?.evidence?.repository;
  if (typeof negotiated === "string" && negotiated !== "") return negotiated;
  return opts.endpoint.replace(/\/+$/, "");
}

/** Every evidence record of the session that belongs to the message, across pages. */
async function readEvidence(client: QerdsClient, repository: string, messageId: string): Promise<QerdsEvidenceRecord[]> {
  const records: QerdsEvidenceRecord[] = [];
  let token: string | undefined;
  for (let page = 0; page < 100; page++) {
    const url = new URL(`${repository.replace(/\/+$/, "")}/evidence`);
    url.searchParams.set("session_id", client.sessionId!);
    if (token !== undefined) url.searchParams.set("continuation_token", token);
    const doc = await client.evidencePage(url);
    if (!Array.isArray(doc.evidence_records)) throw new Error("evidence repository: no evidence_records");
    for (const r of doc.evidence_records) {
      if (!isObject(r) || typeof r.evidence_id !== "string" || typeof r.event_type !== "string") {
        throw new Error("evidence repository: a malformed record");
      }
      // The session's records of other messages are not this message's evidence.
      if (r.original_message_id === messageId) records.push(r as QerdsEvidenceRecord);
    }
    if (typeof doc.continuation_token !== "string" || doc.continuation_token === "") return records;
    token = doc.continuation_token;
  }
  throw new Error("evidence repository: more than 100 pages");
}

async function pollEvidence(
  client: QerdsClient,
  opts: SendQerdsOptions,
  session: SendQerdsResult["session"],
  messageId: string,
): Promise<{ evidence: QerdsEvidenceRecord[]; confirmed: boolean }> {
  const until = opts.evidence?.until ?? DEFAULT_UNTIL;
  const interval = opts.evidence?.intervalMs ?? 5_000;
  const deadline = Date.now() + (opts.evidence?.timeoutMs ?? 90_000);
  const repository = repositoryUrl(opts, session);
  for (;;) {
    const evidence = await readEvidence(client, repository, messageId);
    if (evidence.some((r) => until.includes(r.event_type))) return { evidence, confirmed: true };
    if (Date.now() + interval > deadline) return { evidence, confirmed: false };
    await new Promise((resolve) => setTimeout(resolve, interval));
  }
}

/**
 * Sends one message as a registered electronic delivery and returns the
 * session, the group, what was sent and the evidence read so far. A refused
 * step throws a QerdsError naming it; a poll that ends without one of
 * `evidence.until` returns `confirmed: false`.
 */
export async function sendQerds(opts: SendQerdsOptions): Promise<SendQerdsResult> {
  checkOptions(opts);
  const client = new QerdsClient(opts);
  const mls = opts.mls ?? tsMlsQerdsGroups();

  const session = await step("session", "wmp.session.create", () => createSession(client, opts));

  const published: Record<string, QerdsKeyPackage[]> = {};
  for (const recipient of opts.recipients) {
    published[recipient] = await step("resolve", recipient, () => resolveRecipient(client, recipient));
  }

  const group = await step("group", "wmp.mls.group.create", async () => {
    const { cipherSuite, keyPackages } = selectKeyPackages(published, acceptedSuites(session.security));
    const created = await mls.createGroup({ cipherSuite, certificates: derChain(opts.credential.chain), keyPackages });
    await client.call(MLSMethod.GroupCreate, {
      wmp: client.meta(),
      group_id: created.groupId,
      cipher_suite: created.cipherSuite,
      group_info: created.groupInfo,
      welcomes: created.welcomes,
    });
    return created;
  });

  const { message, epoch } = await step("deliver", "wmp.message.deliver", () => deliver(client, opts, group));

  const result: SendQerdsResult = {
    session,
    group: { id: group.groupId, cipherSuite: group.cipherSuite, epoch },
    message,
    evidence: [],
    confirmed: false,
  };
  if (opts.evidence?.poll === false) return result;
  const polled = await step("evidence", "the evidence repository", () => pollEvidence(client, opts, session, message.id));
  return { ...result, ...polled };
}
