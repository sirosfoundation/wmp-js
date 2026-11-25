import { describe, it, expect } from "vitest";
import {
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  emptyPskIndex,
  encodeMlsMessage,
  generateKeyPackage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processMessage,
  acceptAll,
  type CiphersuiteImpl,
  type KeyPackage,
  type MLSMessage,
  type PrivateKeyPackage,
} from "ts-mls";
import { sendQerds, QerdsError, type SendQerdsOptions } from "../src/qerds.js";
import { canonicalize, contentObject, verifyContentSignature } from "../src/signature.js";
import { requestProofFromHeader, verifyRequestProof, webCryptoProofSigner } from "../src/proof.js";
import { WMPError } from "../src/jsonrpc.js";
import { certFor, ecKey } from "./support/certs.js";

const ENDPOINT = "https://erds.example.com/wmp";
const SENDER = "ebcore:iso6523:0007:5595421925";
const BOB = "ebcore:iso6523:0106:99900817";
const CAROL = "ebcore:iso6523:0106:11111111";
const SID = "ses-qerds-1";
const SUITES: Record<number, string> = {
  1: "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519",
  2: "MLS_128_DHKEMP256_AES128GCM_SHA256_P256",
};

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");

interface Recipient {
  suite: number;
  impl: CiphersuiteImpl;
  pub: KeyPackage;
  priv: PrivateKeyPackage;
  wire: string;
}

async function recipient(id: string, suite: number): Promise<Recipient> {
  const impl = await getCiphersuiteImpl(getCiphersuiteFromName(SUITES[suite] as never));
  const kp = await generateKeyPackage(
    { credentialType: "basic", identity: new TextEncoder().encode(id) },
    defaultCapabilities(),
    defaultLifetime,
    [],
    impl,
  );
  const wire = b64url(encodeMlsMessage({ version: "mls10", wireformat: "mls_key_package", keyPackage: kp.publicPackage } as MLSMessage));
  return { suite, impl, pub: kp.publicPackage, priv: kp.privatePackage, wire };
}

interface Call {
  method: string;
  url: string;
  headers: Headers;
  body?: { id: string; method: string; params: Record<string, any> };
}

/** An ERDS that answers the sender's requests and records them. */
class FakeErds {
  calls: Call[] = [];
  recipients: Record<string, Recipient[]> = {};
  security: Record<string, unknown> = { mode: "mls", cipher_suites: [1, 2] };
  /** JSON-RPC errors to answer a method with. */
  refuse: Record<string, { code: number; message: string }> = {};
  /** Overrides of a resolve answer, by type. */
  resolveAnswer: Record<string, (uri: string) => unknown> = {};
  /** Evidence pages served in order; the last one repeats. */
  evidencePages: Array<Record<string, unknown>> = [{ evidence_records: [] }];
  private evidenceReads = 0;
  resolveCount = 0;

  fetch: typeof globalThis.fetch = async (input, init) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    const method = init?.method ?? "GET";
    if (method === "GET") {
      this.calls.push({ method, url, headers });
      if (this.stallEvidence) {
        return new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => reject(new DOMException("aborted", "AbortError")));
        });
      }
      const page = this.evidencePages[Math.min(this.evidenceReads++, this.evidencePages.length - 1)];
      return new Response(JSON.stringify(page), { status: 200, headers: { "Content-Type": "application/json" } });
    }
    const body = JSON.parse(String(init?.body));
    this.calls.push({ method, url, headers, body });
    const refused = this.refuse[body.method];
    const answer = refused ? { jsonrpc: "2.0", id: body.id, error: refused } : { jsonrpc: "2.0", id: body.id, result: this.result(body) };
    return new Response(JSON.stringify(answer), { status: 200, headers: { "Content-Type": "application/json" } });
  };

  /** When set, an evidence read never answers (until it is aborted). */
  stallEvidence = false;

  private result(body: { method: string; params: Record<string, any> }): unknown {
    switch (body.method) {
      case "wmp.session.create":
        return { wmp: { version: "0.1", session_id: SID }, security: this.security, capabilities: body.params.capabilities_offered };
      case "wmp.resolve": {
        const { type, uri } = body.params;
        if (this.resolveAnswer[type]) return this.resolveAnswer[type](uri);
        if (type === "participant") return { type, uri, resolved: true, qerds_capable: true };
        // A fresh id per resolve, as a single-use KeyPackage store answers.
        const n = ++this.resolveCount;
        return {
          type,
          uri,
          key_packages: (this.recipients[uri] ?? []).map((r) => ({ id: `kp-${n}`, cipher_suite: r.suite, key_package: r.wire })),
        };
      }
      default:
        return { wmp: { version: "0.1", session_id: SID } };
    }
  }

  of(method: string): Call[] {
    return this.calls.filter((c) => c.body?.method === method);
  }
}

async function credential() {
  const keys = await ecKey();
  const leaf = await certFor(keys.publicKey);
  const issuer = await certFor((await ecKey()).publicKey);
  return { keys, chain: [leaf, issuer], signer: webCryptoProofSigner(keys.privateKey) };
}

async function setup(over: Partial<SendQerdsOptions> = {}) {
  const erds = new FakeErds();
  erds.recipients[BOB] = [await recipient(BOB, 2)];
  const cred = await credential();
  const opts: SendQerdsOptions = {
    endpoint: ENDPOINT,
    sender: SENDER,
    recipients: [BOB],
    credential: { chain: cred.chain, signer: cred.signer },
    message: { body: { text: "the consignment" } },
    evidence: { poll: false },
    fetch: erds.fetch,
    ...over,
  };
  return { erds, cred, opts };
}

/** Joins the group as a recipient and decrypts the delivered ciphertext. */
async function open(erds: FakeErds, who: string): Promise<Record<string, unknown>> {
  const r = erds.recipients[who].find((kp) => kp.suite === erds.of("wmp.mls.group.create")[0].body!.params.cipher_suite)!;
  const create = erds.of("wmp.mls.group.create")[0].body!.params;
  const welcome = decodeMlsMessage(Buffer.from(create.welcomes[who], "base64url"), 0)![0];
  if (welcome.wireformat !== "mls_welcome") throw new Error("not a Welcome");
  const state = await joinGroup(welcome.welcome, r.pub, r.priv, emptyPskIndex, r.impl);
  expect(b64url(state.groupContext.groupId)).toBe(create.group_id);
  const deliver = erds.of("wmp.message.deliver")[0].body!.params;
  expect(Number(state.groupContext.epoch)).toBe(deliver.wmp.epoch);
  const msg = decodeMlsMessage(Buffer.from(deliver.ciphertext, "base64url"), 0)![0];
  const out = await processMessage(msg as never, state, emptyPskIndex, acceptAll, r.impl);
  if (out.kind !== "applicationMessage") throw new Error("not an application message");
  return JSON.parse(new TextDecoder().decode(out.message));
}

describe("sendQerds", () => {
  it("runs the consignment: session, resolves, group, deliver", async () => {
    const { erds, cred, opts } = await setup();
    const result = await sendQerds(opts);

    expect(erds.calls.map((c) => c.body?.method)).toEqual([
      "wmp.session.create",
      "wmp.resolve",
      "wmp.resolve",
      "wmp.mls.group.create",
      "wmp.message.deliver",
    ]);
    expect(erds.calls.every((c) => c.url === ENDPOINT)).toBe(true);

    const create = erds.of("wmp.session.create")[0];
    expect(create.headers.get("Wmp-Session-Id")).toBeNull();
    expect(create.headers.get("Authorization")).toBeNull();
    expect(create.body!.params).toMatchObject({
      wmp: { version: "0.1", sender: SENDER },
      participants: ["x509:san:dns:erds.example.com"],
      auth: { type: "mtls" },
      security: { mode: "mls", cipher_suites: [1, 2] },
      ttl: 3600,
    });
    expect(create.body!.params.wmp.session_id).toBeUndefined();
    expect(create.body!.params.capabilities_offered.evidence.event_types).toContain("delivery_confirmed");

    expect(erds.of("wmp.resolve").map((c) => [c.body!.params.type, c.body!.params.uri])).toEqual([
      ["participant", BOB],
      ["mls_key_packages", BOB],
    ]);
    for (const c of erds.calls.slice(1)) {
      expect(c.headers.get("Wmp-Session-Id")).toBe(SID);
      expect(c.body!.params.wmp.session_id).toBe(SID);
    }

    const group = erds.of("wmp.mls.group.create")[0].body!.params;
    expect(group.cipher_suite).toBe(2);
    expect(Object.keys(group.welcomes)).toEqual([BOB]);
    const info = decodeMlsMessage(Buffer.from(group.group_info, "base64url"), 0)![0];
    expect(info.wireformat).toBe("mls_group_info");

    expect(result.session.id).toBe(SID);
    expect(result.group).toEqual({ id: group.group_id, cipherSuite: 2, epoch: 1 });
    expect(result.confirmed).toBe(false);
    expect(cred.chain).toHaveLength(2);
  });

  it("delivers the ciphertext as the only content field, signed and asserted", async () => {
    const { erds, cred, opts } = await setup();
    const result = await sendQerds(opts);
    const call = erds.of("wmp.message.deliver")[0].body!;
    const x5c = cred.chain.map((c) => Buffer.from(c).toString("base64"));

    expect(Object.keys(call.params).sort()).toEqual(["ciphertext", "wmp"]);
    expect(call.params.wmp).toMatchObject({
      session_id: SID,
      sender: SENDER,
      encrypted: true,
      epoch: 1,
      identity_assertions: [{ type: "x509_chain", x5c }],
    });
    expect(call.id).toBe(result.message.id);
    expect(result.message.content).toEqual({ ciphertext: call.params.ciphertext });

    // The signature covers params without wmp, and is made with the credential's key.
    const verified = await verifyContentSignature(call.params.wmp.signature, contentObject(call.params), { verifyChain: () => {} });
    expect(verified.alg).toBe("ES256");
    expect(verified.chain!.map((c) => Buffer.from(c).toString("base64"))).toEqual(x5c);
    expect(result.message.signature).toBe(call.params.wmp.signature);

    // The recipient joins with the Welcome and reads the plaintext content object.
    const plaintext = await open(erds, BOB);
    expect(plaintext).toEqual({ to: [BOB], content_type: "application/json", body: { text: "the consignment" } });
    expect(result.message.plaintext).toEqual(plaintext);
  });

  it("carries the sender's certificate chain as the MLS leaf credential", async () => {
    const { erds, cred, opts } = await setup();
    await sendQerds(opts);
    const r = erds.recipients[BOB][0];
    const create = erds.of("wmp.mls.group.create")[0].body!.params;
    const welcome = decodeMlsMessage(Buffer.from(create.welcomes[BOB], "base64url"), 0)![0];
    if (welcome.wireformat !== "mls_welcome") throw new Error("not a Welcome");
    const state = await joinGroup(welcome.welcome, r.pub, r.priv, emptyPskIndex, r.impl);
    const leaves = state.ratchetTree.filter((n) => n?.nodeType === "leaf").map((n) => (n as any).leaf.credential);
    const x509 = leaves.filter((c) => c.credentialType === "x509");
    expect(x509).toHaveLength(1);
    expect(x509[0].certificates.map((c: Uint8Array) => Buffer.from(c).toString("base64"))).toEqual(
      cred.chain.map((c) => Buffer.from(c).toString("base64")),
    );
  });

  it("uses a unique message id per send and resolves a KeyPackage per group", async () => {
    const { erds, opts } = await setup();
    const first = await sendQerds(opts);
    const second = await sendQerds(opts);
    expect(first.message.id).not.toBe(second.message.id);
    expect(first.group.id).not.toBe(second.group.id);
    expect(erds.of("wmp.resolve").filter((c) => c.body!.params.type === "mls_key_packages")).toHaveLength(2);
    const ids = erds.calls.map((c) => c.body!.id);
    expect(new Set(ids).size).toBe(ids.length);
    expect((await sendQerds({ ...opts, message: { body: 1, id: "msg-mine" } })).message.id).toBe("msg-mine");
  });

  it("proves every request when auth is dpop", async () => {
    const { erds, opts } = await setup({ auth: "dpop", evidence: { timeoutMs: 5_000, intervalMs: 60_000 } });
    await sendQerds(opts);
    expect(erds.of("wmp.session.create")[0].body!.params.auth).toEqual({ type: "dpop" });
    expect(erds.calls).toHaveLength(6);
    const jtis = new Set<string>();
    for (const [i, c] of erds.calls.entries()) {
      const proof = requestProofFromHeader(c.headers.get("Authorization"));
      expect(proof).toBeDefined();
      const expected = i === 0 ? { noSession: true } : { sessionId: SID };
      const v = await verifyRequestProof(proof!, { method: c.method, url: c.url, ...expected }, { verifyChain: () => {} });
      expect(v.chain).toHaveLength(2);
      jtis.add(v.claims.jti);
    }
    expect(jtis.size).toBe(6);
    // The evidence read is proved as the GET it is, on the repository URL.
    const get = erds.calls[5];
    expect(get.method).toBe("GET");
    expect(get.url).toBe(`${ENDPOINT}/evidence?session_id=${SID}`);
  });

  it("commits to the plaintext when asked", async () => {
    const { erds, opts } = await setup({ plaintextHash: true });
    const result = await sendQerds(opts);
    const params = erds.of("wmp.message.deliver")[0].body!.params;
    expect(Object.keys(params).sort()).toEqual(["ciphertext", "plaintext_hash", "wmp"]);
    const plaintext = await open(erds, BOB);
    expect(Buffer.from(plaintext.salt as string, "base64url").length).toBeGreaterThanOrEqual(16);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonicalize(plaintext))));
    expect(params.plaintext_hash).toEqual({ algorithm: "sha-256", value: b64url(digest) });
    // The signature covers the commitment.
    await verifyContentSignature(params.wmp.signature, contentObject(params), { verifyChain: () => {} });
    await expect(
      verifyContentSignature(params.wmp.signature, { ciphertext: params.ciphertext }, { verifyChain: () => {} }),
    ).rejects.toThrow(/signature/);
    expect(result.message.content).toEqual(contentObject(params));
  });

  it("adds every recipient in one group on a suite they share", async () => {
    const { erds, opts } = await setup({ recipients: [BOB, CAROL] });
    erds.recipients[BOB] = [await recipient(BOB, 1), await recipient(BOB, 2)];
    erds.recipients[CAROL] = [await recipient(CAROL, 2)];
    const result = await sendQerds(opts);
    expect(result.group.cipherSuite).toBe(2);
    const group = erds.of("wmp.mls.group.create")[0].body!.params;
    expect(Object.keys(group.welcomes).sort()).toEqual([BOB, CAROL].sort());
    for (const who of [BOB, CAROL]) {
      expect((await open(erds, who)).to).toEqual([BOB, CAROL]);
    }
  });

  it("takes the suite from the resolved KeyPackage, within what the session accepts", async () => {
    const { erds, opts } = await setup();
    erds.recipients[BOB] = [await recipient(BOB, 1)];
    expect((await sendQerds(opts)).group.cipherSuite).toBe(1);

    // The selected suite binds even when the list is wider.
    erds.security = { mode: "mls", cipher_suites: [1, 2], cipher_suite: 2 };
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe("group");
    expect(erds.of("wmp.message.deliver")).toHaveLength(1);
  });

  it.each<[string, string, unknown]>([
    ["not QERDS-capable", "participant", { resolved: true, qerds_capable: false }],
    ["without qerds_capable", "participant", { resolved: true }],
    ["unresolved", "participant", { resolved: false, qerds_capable: true }],
    ["answered with null metadata", "participant", { metadata: null }],
    ["without KeyPackages", "mls_key_packages", { key_packages: [] }],
    ["with null KeyPackages", "mls_key_packages", { key_packages: null }],
    ["with a malformed KeyPackage", "mls_key_packages", { key_packages: [{ cipher_suite: 2, key_package: null }] }],
  ])("stops at a recipient %s", async (_name, type, answer) => {
    const { erds, opts } = await setup();
    erds.resolveAnswer[type] = () => answer;
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe("resolve");
    expect(erds.of("wmp.mls.group.create")).toHaveLength(0);
    expect(erds.of("wmp.message.deliver")).toHaveLength(0);
  });

  it("reads a resolve answer from its metadata member too", async () => {
    const { erds, opts } = await setup();
    const kp = erds.recipients[BOB][0];
    erds.resolveAnswer.participant = (uri) => ({ type: "participant", uri, metadata: { resolved: true, qerds_capable: true } });
    erds.resolveAnswer.mls_key_packages = (uri) => ({
      type: "mls_key_packages",
      uri,
      metadata: { key_packages: [{ cipher_suite: kp.suite, key_package: kp.wire }] },
    });
    expect((await sendQerds(opts)).group.cipherSuite).toBe(2);
  });

  it.each([
    ["wmp.session.create", "session"],
    ["wmp.resolve", "resolve"],
    ["wmp.mls.group.create", "group"],
    ["wmp.message.deliver", "deliver"],
  ])("names the step a refused %s belongs to", async (method, step) => {
    const { erds, opts } = await setup();
    erds.refuse[method] = { code: -31010, message: "Signature invalid" };
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe(step);
    expect(err.cause).toBeInstanceOf(WMPError);
    expect((err.cause as WMPError).code).toBe(-31010);
    expect(erds.calls.at(-1)!.body!.method).toBe(method);
  });

  it("polls the evidence of its own message until the delivery is confirmed", async () => {
    const { erds, opts } = await setup({ message: { body: "x", id: "msg-1" }, evidence: { intervalMs: 1, timeoutMs: 5_000 } });
    const rec = (id: string, type: string, msg = "msg-1") => ({ evidence_id: id, event_type: type, original_message_id: msg });
    erds.evidencePages = [
      { evidence_records: [rec("evi-1", "submission_accepted"), rec("evi-x", "delivery_confirmed", "msg-other")] },
      { evidence_records: [rec("evi-1", "submission_accepted")], continuation_token: "page-2" },
      { evidence_records: [rec("evi-2", "delivery_confirmed")], continuation_token: null },
    ];
    const result = await sendQerds(opts);
    expect(result.confirmed).toBe(true);
    expect(result.evidence.map((r) => r.evidence_id)).toEqual(["evi-1", "evi-2"]);
    const gets = erds.calls.filter((c) => c.method === "GET");
    expect(gets.map((c) => c.url)).toEqual([
      `${ENDPOINT}/evidence?session_id=${SID}`,
      `${ENDPOINT}/evidence?session_id=${SID}`,
      `${ENDPOINT}/evidence?session_id=${SID}&continuation_token=page-2`,
    ]);
    expect(gets.every((c) => c.headers.get("Wmp-Session-Id") === SID)).toBe(true);
  });

  it("returns what it read when the poll ends unconfirmed", async () => {
    const { erds, opts } = await setup({ message: { body: "x", id: "msg-1" }, evidence: { intervalMs: 1, timeoutMs: 20 } });
    erds.evidencePages = [{ evidence_records: [{ evidence_id: "evi-1", event_type: "submission_accepted", original_message_id: "msg-1" }] }];
    const result = await sendQerds(opts);
    expect(result.confirmed).toBe(false);
    expect(result.evidence).toHaveLength(1);
  });

  it("reads the repository the session negotiated", async () => {
    const { erds, opts } = await setup({
      evidence: { timeoutMs: 5_000, intervalMs: 60_000 },
      capabilities: { evidence: { event_types: ["delivery_confirmed"], repository: "https://evidence.example.com/api/" } },
    });
    await sendQerds(opts);
    expect(erds.calls.at(-1)!.url).toBe(`https://evidence.example.com/api/evidence?session_id=${SID}`);
  });

  it.each([
    ["no evidence_records", { evidence_records: null }],
    ["a malformed record", { evidence_records: [{ event_type: "delivery_confirmed" }] }],
  ])("refuses a repository answer with %s", async (_name, page) => {
    const { erds, opts } = await setup({ evidence: { timeoutMs: 5_000, intervalMs: 60_000 } });
    erds.evidencePages = [page];
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe("evidence");
  });

  it.each<[string, Partial<SendQerdsOptions>]>([
    ["a relative endpoint", { endpoint: "/wmp" }],
    ["no sender", { sender: "" }],
    ["no recipients", { recipients: [] }],
    ["a repeated recipient", { recipients: [BOB, BOB] }],
    ["an empty chain", { credential: { chain: [], signer: { alg: "ES256", sign: () => new Uint8Array() } } }],
    ["an unknown auth", { auth: "bearer" as never }],
    ["no body", { message: {} as never }],
  ])("refuses %s before any request", async (_name, over) => {
    const { erds, opts } = await setup(over);
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe("config");
    expect(erds.calls).toHaveLength(0);
  });

  it.each(["tls", "none", undefined])("refuses a session whose security mode is %s", async (mode) => {
    const { erds, opts } = await setup();
    erds.security = { mode };
    const err = await sendQerds(opts).catch((e) => e);
    expect(err).toBeInstanceOf(QerdsError);
    expect(err.step).toBe("session");
    expect(erds.calls).toHaveLength(1);
  });

  it("accepts an mls-optional session", async () => {
    const { erds, opts } = await setup();
    erds.security = { mode: "mls-optional", cipher_suites: [2] };
    expect((await sendQerds(opts)).group.cipherSuite).toBe(2);
  });

  it("reports what was sent when the deliver fails", async () => {
    const { erds, opts } = await setup();
    erds.refuse["wmp.message.deliver"] = { code: -32603, message: "Internal error" };
    const err = await sendQerds(opts).catch((e) => e);
    expect(err.step).toBe("deliver");
    const call = erds.of("wmp.message.deliver")[0].body!;
    expect(err.sent.id).toBe(call.id);
    expect(err.sent.content).toEqual({ ciphertext: call.params.ciphertext });
    expect(err.sent.signature).toBe(call.params.wmp.signature);
    expect(err.sent.plaintext.to).toEqual([BOB]);
  });

  it("ends the poll unconfirmed when the repository stalls past the timeout", async () => {
    const { erds, opts } = await setup({ evidence: { timeoutMs: 50 } });
    erds.stallEvidence = true;
    const result = await sendQerds(opts);
    expect(result.confirmed).toBe(false);
    expect(result.evidence).toEqual([]);
    expect(result.message.id).toBeTruthy();
  });
});
