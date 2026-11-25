import { describe, it, expect, vi } from "vitest";
import {
  createRequestProof,
  verifyRequestProof,
  requestProofFromHeader,
  webCryptoProofSigner,
  MemoryRequestProofReplayCache,
  RequestProofError,
  type RequestProofSigner,
  type VerifyRequestProofOptions,
} from "../src/proof.js";
import { HttpSseTransport } from "../src/transport.js";
import { createRequest } from "../src/jsonrpc.js";

const EPOCH = 1795526400;
const now = () => EPOCH;
const RELAY = "https://relay.example.com/wmp";
const SID = "ses-a1b2c3d4";

// A proof made by go-wmp (pkg/wmp/proof) for POST RELAY on SID at EPOCH, with
// a real two-certificate x5c chain (leaf SAN https://wallet.example.com).
const GO_PROOF =
  "eyJhbGciOiJFUzI1NiIsInR5cCI6IndtcC1wcm9vZitqd3QiLCJ4NWMiOlsiTUlJQmJEQ0NBUktnQXdJQkFnSUJBakFLQmdncWhrak9QUVFEQWpBU01SQXdEZ1lEVlFRREV3ZDBaWE4wSUdOaE1CNFhEVEkyTVRFeU5ERXlNakF3TUZvWERUSTJNVEV5TkRFME1qQXdNRm93RVRFUE1BMEdBMVVFQXhNR2QyRnNiR1YwTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFM1RvaVZWZTVKQ3V5d3BuYjZRZDJFb1ltMzdRdGlPdEpjSDJBaDBuS3oyMkdSYUdOYlpoL3lXOGFlamUya0xMUWRSeHRHbHA4QVE0SlZMVEJZY3JuVnFOYU1GZ3dEZ1lEVlIwUEFRSC9CQVFEQWdlQU1COEdBMVVkSXdRWU1CYUFGUEZEUGJVVlpsbmE4YmpTaDBSTnpHTkxnQ290TUNVR0ExVWRFUVFlTUJ5R0dtaDBkSEJ6T2k4dmQyRnNiR1YwTG1WNFlXMXdiR1V1WTI5dE1Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRQ2QwR3dpWHpyWmUvdlZNNGp4M2ZDK3ljUXZqbDZRbUtYWmdYNEZkZUVWNFFJZ0RLZUFqSmN0UVY3bnpzOERDMWg4YjVaZDY0d01UeDg2aG1zTkk3OHIwYUE9IiwiTUlJQlZEQ0IrNkFEQWdFQ0FnRUJNQW9HQ0NxR1NNNDlCQU1DTUJJeEVEQU9CZ05WQkFNVEIzUmxjM1FnWTJFd0hoY05Nall4TVRJME1USXlNREF3V2hjTk1qWXhNVEkwTVRReU1EQXdXakFTTVJBd0RnWURWUVFERXdkMFpYTjBJR05oTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFcU10SDJ4VlEyNHJyQXRRNldrbHRNdXI5dkpydkJ2VzJhSVlSUUNQVGdYVGhXTDNvSnYza2JLMkljeW5RSEMzZXE3TWdDcmRjZXRORmFBWEwxQzFYbDZOQ01FQXdEZ1lEVlIwUEFRSC9CQVFEQWdJRU1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZQRkRQYlVWWmxuYThialNoMFJOekdOTGdDb3RNQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJQlVDb2ViUWJXMHFpY2VjUFFwOHVvOCtrc2poOHNrYkNzdnFudkdQdGZTeEFpRUFvYUgvK01kMzhySjBtUnkzdDhHYndyaDZ3djhEL3VQMkpGRU13czJrbXFjPSJdfQ.eyJodG0iOiJQT1NUIiwiaHR1IjoiaHR0cHM6Ly9yZWxheS5leGFtcGxlLmNvbS93bXAiLCJpYXQiOjE3OTU1MjY0MDAsImp0aSI6IjdlMDc5OWZhZGVjZmYyOGQyNmQ5NGNjZTI5MDJlNGU5Iiwic2lkIjoic2VzLWExYjJjM2Q0In0.OOXjHPEo5HzUkf4mYc8UVBnaCVGIR6pDkj3dZcj9BJxlPQD5RmZCxP6SbZGUs6gBfpTAg8n-xsC_REV2SpDY7w";

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const unb64url = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));
const json = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));

async function ecKey(curve = "P-256"): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
}

function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  const head = len < 128 ? [tag, len] : len < 256 ? [tag, 0x81, len] : [tag, 0x82, len >> 8, len & 0xff];
  const out = new Uint8Array(head.length + len);
  out.set(head);
  let at = head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

/** A certificate-shaped DER structure around a public key (unsigned: chain validation is the caller's). */
async function certFor(pub: CryptoKey): Promise<Uint8Array> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
  const empty = tlv(0x30);
  const tbs = tlv(0x30, tlv(0xa0, tlv(0x02, new Uint8Array([2]))), tlv(0x02, new Uint8Array([1])), empty, empty, empty, empty, spki);
  return tlv(0x30, tbs, empty, tlv(0x03, new Uint8Array([0])));
}

const trustAll: VerifyRequestProofOptions = { verifyChain: () => {}, now };
const expectPost = { method: "POST", url: RELAY, sessionId: SID };

async function x5cFixture(curve = "P-256") {
  const keys = await ecKey(curve);
  const signer = webCryptoProofSigner(keys.privateKey);
  const x5c = [await certFor(keys.publicKey)];
  const make = (over: Record<string, unknown> = {}) =>
    createRequestProof({ signer, x5c, method: "POST", url: RELAY, sessionId: SID, now, ...over });
  return { keys, signer, x5c, make };
}

/** Re-signs a proof after editing its header and payload, to present what createRequestProof never makes. */
async function resign(proof: string, signer: RequestProofSigner, edit: (h: any, p: any) => void): Promise<string> {
  const [h, p] = proof.split(".");
  const header = json(h);
  const payload = json(p);
  edit(header, payload);
  const input = b64url(Buffer.from(JSON.stringify(header))) + "." + b64url(Buffer.from(JSON.stringify(payload)));
  return input + "." + b64url(await signer.sign(new TextEncoder().encode(input)));
}

describe("request proof (WMP Core 4.4.8)", () => {
  it("makes the header and the JCS payload of the specification", async () => {
    const { make } = await x5cFixture();
    const [h, p, s] = (await make()).split(".");
    const header = json(h);
    expect(header.alg).toBe("ES256");
    expect(header.typ).toBe("wmp-proof+jwt");
    expect(header.x5c).toHaveLength(1);
    expect(header.kid).toBeUndefined();
    const payload = Buffer.from(p, "base64url").toString("utf8");
    const jti = JSON.parse(payload).jti;
    // The member order and spacing of the spec's example payload.
    expect(payload).toBe(
      '{"htm":"POST","htu":"https://relay.example.com/wmp","iat":1795526400,"jti":"' + jti + '","sid":"ses-a1b2c3d4"}',
    );
    expect(unb64url(s)).toHaveLength(64);
  });

  it.each(["P-256", "P-384", "P-521"])("round-trips an x5c proof on %s", async (curve) => {
    const { make, x5c } = await x5cFixture(curve);
    const verifyChain = vi.fn();
    const v = await verifyRequestProof(await make(), expectPost, { verifyChain, now });
    expect(v.claims.sid).toBe(SID);
    expect(v.alg).toBe({ "P-256": "ES256", "P-384": "ES384", "P-521": "ES512" }[curve]);
    expect(verifyChain).toHaveBeenCalledOnce();
    expect(Buffer.from(verifyChain.mock.calls[0][0][0]).equals(Buffer.from(x5c[0]))).toBe(true);
  });

  it("round-trips a kid proof with Ed25519, leaving the query out of htu", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const kid = "did:web:wallet.example.com#key-1";
    const proof = await createRequestProof({
      signer: webCryptoProofSigner(keys.privateKey),
      kid,
      method: "GET",
      url: "https://relay.example.com/wmp/events?session_id=s1",
      sessionId: "s1",
      now,
    });
    const resolveKey = (k: string) => (k === kid ? keys.publicKey : undefined);
    const v = await verifyRequestProof(
      proof,
      { method: "GET", url: "https://RELAY.example.com:443/wmp/events?session_id=s1", sessionId: "s1" },
      { resolveKey, now },
    );
    expect(v.kid).toBe(kid);
    expect(v.chain).toBeUndefined();
    expect(v.claims.htu).toBe("https://relay.example.com/wmp/events");
    await expect(
      verifyRequestProof(
        proof,
        { method: "GET", url: "https://relay.example.com/wmp/events", sessionId: "s1" },
        { resolveKey: () => undefined, now },
      ),
    ).rejects.toThrow(RequestProofError);
  });

  it("verifies a proof made by go-wmp", async () => {
    const verifyChain = vi.fn();
    const v = await verifyRequestProof(GO_PROOF, expectPost, { verifyChain, now });
    expect(v.claims).toMatchObject({ htm: "POST", htu: RELAY, iat: EPOCH, sid: SID });
    expect(verifyChain.mock.calls[0][0]).toHaveLength(2);
    await expect(
      verifyRequestProof(GO_PROOF, { ...expectPost, sessionId: "ses-other" }, { verifyChain, now }),
    ).rejects.toThrow(/sid/);
  });

  it("carries and checks the access token hash", async () => {
    // The access token and its ath of the example in RFC 9449 section 7.1.
    const accessToken = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU";
    const { make } = await x5cFixture();
    const proof = await make({ accessToken });
    const v = await verifyRequestProof(proof, { ...expectPost, accessToken }, trustAll);
    expect(v.claims.ath).toBe("fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo");
    await expect(verifyRequestProof(proof, expectPost, trustAll)).rejects.toThrow(/ath/);
    await expect(verifyRequestProof(proof, { ...expectPost, accessToken: "other" }, trustAll)).rejects.toThrow(/ath/);
    await expect(verifyRequestProof(await make(), { ...expectPost, accessToken }, trustAll)).rejects.toThrow(/ath/);
  });

  it("makes and verifies the sid-less proof of a session create", async () => {
    const { make } = await x5cFixture();
    const createProof = await make({ sessionId: undefined });
    const payload = Buffer.from(createProof.split(".")[1], "base64url").toString("utf8");
    expect(payload).not.toContain('"sid"');
    expect(payload.startsWith('{"htm":"POST","htu":"https://relay.example.com/wmp","iat":1795526400,"jti":"')).toBe(true);
    const create = { method: "POST", url: RELAY, noSession: true };
    const v = await verifyRequestProof(createProof, create, trustAll);
    expect(v.claims.sid).toBeUndefined();
    // It is not a proof for a session, and a session's proof does not pass where none is named.
    await expect(verifyRequestProof(createProof, expectPost, trustAll)).rejects.toThrow(/sid/);
    await expect(verifyRequestProof(await make(), create, trustAll)).rejects.toThrow(/sid/);
  });

  it("returns the session to the caller when none is expected", async () => {
    const { make } = await x5cFixture();
    const v = await verifyRequestProof(await make(), { method: "POST", url: RELAY }, trustAll);
    expect(v.claims.sid).toBe(SID);
  });

  it.each<[string, Record<string, unknown>, VerifyRequestProofOptions]>([
    ["another session", { sessionId: "ses-other" }, trustAll],
    ["another method", { method: "GET" }, trustAll],
    ["another path", { url: "https://relay.example.com/other" }, trustAll],
    ["another host", { url: "https://evil.example.com/wmp" }, trustAll],
    ["a stale proof", {}, { ...trustAll, now: () => EPOCH + 31 }],
    ["a proof from the future", {}, { ...trustAll, now: () => EPOCH - 31 }],
    [
      "an untrusted chain",
      {},
      {
        now,
        verifyChain: () => {
          throw new Error("untrusted");
        },
      },
    ],
    ["a chain when none is accepted", {}, { now, resolveKey: () => undefined }],
    ["an algorithm that is not accepted", {}, { ...trustAll, algorithms: ["EdDSA"] }],
  ])("refuses %s", async (_name, over, opts) => {
    const { make } = await x5cFixture();
    await expect(verifyRequestProof(await make(), { ...expectPost, ...over }, opts)).rejects.toThrow(RequestProofError);
  });

  it("accepts a proof at the edge of the tolerance", async () => {
    const { make } = await x5cFixture();
    await expect(
      verifyRequestProof(await make(), expectPost, { ...trustAll, now: () => EPOCH + 30 }),
    ).resolves.toBeDefined();
  });

  it.each<[string, (h: any, p: any) => void]>([
    ["a wrong typ", (h) => void (h.typ = "dpop+jwt")],
    ["no typ", (h) => void delete h.typ],
    ["alg none", (h) => void (h.alg = "none")],
    ["the alg of another curve", (h) => void (h.alg = "ES384")],
    ["x5c and kid together", (h) => void (h.kid = "k")],
    ["neither x5c nor kid", (h) => void delete h.x5c],
    ["an empty x5c", (h) => void (h.x5c = [])],
    ["a null x5c", (h) => void (h.x5c = null)],
    ["an x5c that is not a certificate", (h) => void (h.x5c = ["AAAA"])],
    ["crit", (h) => void (h.crit = ["x"])],
    ["a null sid", (_h, p) => void (p.sid = null)],
    ["an empty sid", (_h, p) => void (p.sid = "")],
    ["a numeric sid", (_h, p) => void (p.sid = 7)],
    ["no jti", (_h, p) => void delete p.jti],
    ["no iat", (_h, p) => void delete p.iat],
    ["a null iat", (_h, p) => void (p.iat = null)],
    ["a string iat", (_h, p) => void (p.iat = "1795526400")],
    ["a fractional iat", (_h, p) => void (p.iat = 1795526400.5)],
    ["an htu with a query", (_h, p) => void (p.htu = RELAY + "?x=1")],
    ["an htu with a fragment", (_h, p) => void (p.htu = RELAY + "#x")],
  ])("refuses %s", async (_name, edit) => {
    const { make, signer } = await x5cFixture();
    const proof = await make();
    // The harness makes a proof that passes when nothing is edited.
    await expect(verifyRequestProof(await resign(proof, signer, () => {}), expectPost, trustAll)).resolves.toBeDefined();
    await expect(verifyRequestProof(await resign(proof, signer, edit), expectPost, trustAll)).rejects.toThrow(
      RequestProofError,
    );
  });

  it("refuses tampering and garbage", async () => {
    const a = await x5cFixture();
    const b = await x5cFixture();
    const [h, p, s] = (await a.make()).split(".");
    const [, p2, s2] = (await b.make({ sessionId: "ses-other" })).split(".");
    const bad = [
      "",
      "a.b",
      "a.b.c.d",
      [h, p, ""].join("."),
      [h, p2, s].join("."), // another payload under this signature
      [h, p, s2].join("."), // another key's signature
      [h + "=", p, s].join("."),
      [h, p, s + "A"].join("."),
    ];
    for (const proof of bad) {
      await expect(verifyRequestProof(proof, expectPost, trustAll)).rejects.toThrow(RequestProofError);
    }
  });

  it("refuses a proof presented twice", async () => {
    const { make } = await x5cFixture();
    const opts = { ...trustAll, replay: new MemoryRequestProofReplayCache(now) };
    const proof = await make();
    await verifyRequestProof(proof, expectPost, opts);
    await expect(verifyRequestProof(proof, expectPost, opts)).rejects.toThrow(/jti/);
    await expect(verifyRequestProof(await make(), expectPost, opts)).resolves.toBeDefined();
  });

  it("forgets replay entries once they expire", () => {
    let t = EPOCH;
    const cache = new MemoryRequestProofReplayCache(() => t);
    expect(cache.seen("a", EPOCH + 60)).toBe(false);
    expect(cache.seen("a", EPOCH + 60)).toBe(true);
    // Between sweeps an expired entry is still not a replay.
    expect(cache.seen("b", EPOCH + 0.5)).toBe(false);
    t = EPOCH + 0.5;
    expect(cache.seen("b", EPOCH + 60)).toBe(false);
    t = EPOCH + 60;
    expect(cache.seen("a", EPOCH + 120)).toBe(false);
  });

  it("refuses to make an incomplete proof", async () => {
    const { signer, x5c } = await x5cFixture();
    const base = { signer, x5c, method: "POST", url: RELAY, sessionId: SID };
    await expect(createRequestProof({ ...base, sessionId: "" })).rejects.toThrow();
    await expect(createRequestProof({ ...base, method: "" })).rejects.toThrow();
    await expect(createRequestProof({ ...base, url: "/wmp" })).rejects.toThrow();
    await expect(createRequestProof({ ...base, kid: "k" })).rejects.toThrow();
    await expect(createRequestProof({ ...base, x5c: undefined })).rejects.toThrow();
  });

  it("reads the proof from an Authorization header", () => {
    expect(requestProofFromHeader("DPoP a.b.c")).toBe("a.b.c");
    expect(requestProofFromHeader("dpop  a.b.c ")).toBe("a.b.c");
    expect(requestProofFromHeader("Bearer a.b.c")).toBeUndefined();
    expect(requestProofFromHeader("DPoP ")).toBeUndefined();
    expect(requestProofFromHeader(null)).toBeUndefined();
  });
});

describe("HttpSseTransport per-request proof", () => {
  const okFetch = () => vi.fn().mockResolvedValue({ ok: true, status: 200, headers: new Headers() });

  it("proves the create without a session and each POST that names one", async () => {
    const fetchMock = okFetch();
    const requestProof = vi.fn(
      async (r: { method: string; url: string; sessionId?: string }) => "proof-" + (r.sessionId ?? "none"),
    );
    const transport = new HttpSseTransport("https://example.com/wmp", "https://example.com/wmp/events", {
      fetch: fetchMock as unknown as typeof fetch,
      authorization: "Bearer tok",
      requestProof,
    });

    // A message that names no session and is not the create keeps the authorization.
    await transport.send(createRequest("wmp.flow.start", { flow_id: "f0" }));
    expect(fetchMock.mock.calls[0][1].headers["Authorization"]).toBe("Bearer tok");
    expect(requestProof).not.toHaveBeenCalled();
    fetchMock.mockClear();

    await transport.send(createRequest("wmp.session.create", {}));
    expect(fetchMock.mock.calls[0][1].headers["Authorization"]).toBe("DPoP proof-none");
    expect(requestProof).toHaveBeenLastCalledWith({ method: "POST", url: "https://example.com/wmp" });

    // Also with a session bound: the create names none.
    transport.setSessionId("ses-0");
    await transport.send(createRequest("wmp.session.create", {}));
    expect(fetchMock.mock.calls[1][1].headers["Authorization"]).toBe("DPoP proof-none");
    fetchMock.mockClear();
    fetchMock.mockResolvedValueOnce({ ok: true, status: 200, headers: new Headers() });
    await transport.send(createRequest("wmp.flow.start", { flow_id: "f0" }));

    transport.setSessionId("ses-1");
    await transport.send(createRequest("wmp.flow.start", { flow_id: "f1" }));
    expect(fetchMock.mock.calls[1][1].headers["Authorization"]).toBe("DPoP proof-ses-1");
    expect(requestProof).toHaveBeenLastCalledWith({
      method: "POST",
      url: "https://example.com/wmp",
      sessionId: "ses-1",
    });

    // A resume is proved for the session it asks for.
    await transport.send(createRequest("wmp.session.resume", { session_id: "ses-2", resumption_token: "t" }));
    expect(fetchMock.mock.calls[2][1].headers["Authorization"]).toBe("DPoP proof-ses-2");
  });

  it("gives the event stream a fetch that adds a fresh proof per connection", async () => {
    const fetchMock = okFetch();
    let n = 0;
    const inits: any[] = [];
    class FakeEventSource {
      readyState = 0;
      onopen: unknown;
      onerror: unknown;
      onmessage: unknown;
      constructor(
        public url: string,
        init?: unknown,
      ) {
        inits.push(init);
      }
      addEventListener() {}
      close() {}
    }
    const transport = new HttpSseTransport("https://example.com/wmp", "https://example.com/wmp/events", {
      fetch: fetchMock as unknown as typeof fetch,
      EventSource: FakeEventSource as unknown as typeof EventSource,
      requestProof: (r) => [r.method, r.url, r.sessionId, ++n].join("|"),
    });
    transport.setSessionId("ses-1");
    transport.connectSSE();
    const streamFetch = inits[0].fetch as (u: string, i?: RequestInit) => Promise<Response>;
    const url = "https://example.com/wmp/events?session_id=ses-1";
    await streamFetch(url, { headers: { Accept: "text/event-stream" } });
    await streamFetch(url, { headers: { Accept: "text/event-stream" } });
    const sent = fetchMock.mock.calls.map(([, init]) => (init.headers as Headers).get("Authorization"));
    expect(sent).toEqual(["DPoP GET|" + url + "|ses-1|1", "DPoP GET|" + url + "|ses-1|2"]);
    expect((fetchMock.mock.calls[0][1].headers as Headers).get("Accept")).toBe("text/event-stream");
  });

  it("round-trips a transport proof through the verifier", async () => {
    const keys = await ecKey();
    const signer = webCryptoProofSigner(keys.privateKey);
    const x5c = [await certFor(keys.publicKey)];
    const fetchMock = okFetch();
    const transport = new HttpSseTransport("https://example.com/wmp", "https://example.com/wmp/events", {
      fetch: fetchMock as unknown as typeof fetch,
      requestProof: (r) => createRequestProof({ signer, x5c, ...r }),
    });
    transport.setSessionId("ses-1");
    await transport.send(createRequest("wmp.flow.start", { flow_id: "f1" }));
    const proof = requestProofFromHeader(fetchMock.mock.calls[0][1].headers["Authorization"])!;
    const v = await verifyRequestProof(
      proof,
      { method: "POST", url: "https://example.com/wmp", sessionId: "ses-1" },
      { verifyChain: () => {} },
    );
    expect(v.claims.sid).toBe("ses-1");
  });
});
