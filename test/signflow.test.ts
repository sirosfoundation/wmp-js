import { describe, it, expect, vi } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  CAPABILITY_TRANSACTION_DATA,
  checkTransactionDataEntry,
  completeSubFlow,
  decodeTransactionData,
  offersTransactionData,
  parseMatchStartParams,
  parseSignSubFlowParams,
  rejectSubFlow,
  transactionDataHash,
  transactionDataUnsupportedData,
  transactionDataUnsupportedError,
  unsupportedTransactionData,
} from "../src/signflow.js";
import { OpenID4xProfile, SubFlowRejectedError } from "../src/openid4x.js";
import { SignFlow, boundNotifier } from "../src/signflow.js";
import { CompletionResultError } from "../src/completion.js";
import { validateSignResult } from "../src/signflow.js";
import { Peer } from "../src/peer.js";
import { WMPError, type Response } from "../src/jsonrpc.js";
import { ErrorCode } from "../src/types.js";
import { MockTransport } from "./mock-transport.js";
import { vectorsDir } from "./vectors.js";

const H = "Zm9yLXRoZS13YWxsZXQtb25seQ";
const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const raw = enc({ type: "urn:eudi:sca:payment:1", credential_ids: ["pay"], payload: { transaction_id: "tx-1" } });
const entry = (extra: Record<string, unknown> = {}) => ({ raw, type: "urn:eudi:sca:payment:1", credential_ids: ["pay"], payload: { transaction_id: "tx-1" }, ...extra });

const sign = (extra: Record<string, unknown> = {}) => ({
  action: "sign_presentation",
  nonce: "n",
  audience: "x509_san_dns:shop.example.com",
  parent_flow_id: "flow-vp-001",
  ...extra,
});

function code(fn: () => unknown): number | undefined {
  try {
    fn();
  } catch (e) {
    return (e as WMPError).code;
  }
  return undefined;
}

describe("transaction_data hashing (spec vectors)", () => {
  const file = JSON.parse(readFileSync(resolve(vectorsDir(), "openid4x/transaction-data-hashes.json"), "utf8")) as {
    vectors: { name: string; raw: string; json: string; hashes: Record<string, string>; noncanonical: boolean }[];
  };

  it("loads the vectors", () => {
    expect(file.vectors.length).toBeGreaterThanOrEqual(10);
  });

  for (const v of file.vectors) {
    it(`${v.name}: hash of raw for every algorithm`, () => {
      for (const [alg, want] of Object.entries(v.hashes)) {
        expect(transactionDataHash(v.raw, alg), `${v.name} ${alg}`).toBe(want);
      }
      // raw decodes to the documented json; re-serializing it must NOT be what is hashed
      expect(Buffer.from(v.raw, "base64url").toString("utf8")).toBe(v.json);
      // Where re-serializing the decoded object changes the bytes, hashing it would bind something else.
      const reserialized = Buffer.from(JSON.stringify(JSON.parse(v.json))).toString("base64url");
      if (reserialized !== v.raw) expect(transactionDataHash(reserialized, "sha-256")).not.toBe(v.hashes["sha-256"]);
    });
  }

  it("refuses an algorithm it cannot compute and a non-ASCII raw", () => {
    expect(() => transactionDataHash("abc", "md5")).toThrow();
    // names inherited from Object.prototype are not algorithms
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty", "valueOf"]) {
      expect(() => transactionDataHash("abc", name), name).toThrow();
    }
    expect(() => transactionDataHash("abcé")).toThrow();
    expect(transactionDataHash("abc")).toBe(transactionDataHash("abc", "sha-256"));
  });
});

describe("checkTransactionDataEntry", () => {
  it("accepts a consistent entry and returns the decoded object", () => {
    expect(checkTransactionDataEntry(entry()).type).toBe("urn:eudi:sca:payment:1");
    expect(decodeTransactionData(raw).payload).toEqual({ transaction_id: "tx-1" });
  });
  it("refuses members that disagree with raw", () => {
    expect(code(() => checkTransactionDataEntry(entry({ type: "urn:other" })))).toBe(-32602);
    expect(code(() => checkTransactionDataEntry(entry({ credential_ids: ["other"] })))).toBe(-32602);
    expect(code(() => checkTransactionDataEntry(entry({ payload: { transaction_id: "tx-2" } })))).toBe(-32602);
    expect(code(() => checkTransactionDataEntry(entry({ transaction_data_hashes_alg: ["sha-512"] })))).toBe(-32602);
  });
  it("does not let a malformed element of the decoded list hide a disagreement", () => {
    const r = enc({ type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256", 7] });
    expect(code(() => checkTransactionDataEntry({ raw: r, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256"] }))).toBe(-32602);
    const r2 = enc({ type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256"] });
    expect(code(() => checkTransactionDataEntry({ raw: r2, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256", ""] }))).toBe(-32602);
    expect(code(() => checkTransactionDataEntry({ raw: r2, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256", "sha-256"] }))).toBe(-32602);
    expect(() => checkTransactionDataEntry({ raw: r2, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256"] })).not.toThrow();
  });

  it("compares hash algorithms ignoring array vs bare string", () => {
    const r = enc({ type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256"] });
    expect(() => checkTransactionDataEntry({ raw: r, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: "sha-256" })).not.toThrow();
  });
  it("refuses a raw that is not base64url JSON object", () => {
    for (const bad of ["!!!", "e30=", "bnVsbA", enc([1]), "A"]) {
      expect(code(() => decodeTransactionData(bad)), bad).toBe(-32602);
    }
  });
});

describe("parseSignSubFlowParams", () => {
  it("accepts the documented shapes and keeps unknown members", () => {
    const p = parseSignSubFlowParams(sign({ response_mode: "direct_post", credentials_to_include: [{ credential_query_id: "pay" }], selection_handle: H, transaction_data: [entry()], future_member: { a: 1 } }));
    expect(p.future_member).toEqual({ a: 1 });
    expect(p.transaction_data).toHaveLength(1);
    expect(() => parseSignSubFlowParams({ action: "generate_proof", audience: "x", credential_response_encryption: { alg: "ECDH-ES", enc: "A256GCM", required: true } })).not.toThrow();
    expect(() => parseSignSubFlowParams({ action: "decrypt_credential_response", parent_flow_id: "p", jwe: "a.b.c.d.e", deferred: false })).not.toThrow();
  });

  it("refuses unknown action, malformed members, the old credentials_to_include shape", () => {
    const cases: [string, unknown][] = [
      ["not object", []],
      ["no action", {}],
      ["unknown action", { action: "no-such-action" }],
      ["empty parent", sign({ parent_flow_id: "" })],
      ["nonce not string", sign({ nonce: 5 })],
      ["client_metadata not object", sign({ client_metadata: [] })],
      ["count 0", { action: "generate_proof", count: 0 }],
      ["count too big", { action: "generate_proof", count: 257 }],
      ["count float", { action: "generate_proof", count: 1.5 }],
      ["deferred string", { action: "decrypt_credential_response", deferred: "no" }],
      ["bad handle", sign({ selection_handle: "x" })],
      ["old credentials_to_include", sign({ credentials_to_include: [{ credential_id: "c", credential_query_id: "pay", disclosed_claims: ["a"] }] })],
      ["credentials_to_include id only", sign({ credentials_to_include: [{ credential_id: "c" }] })],
      ["sign_presentation without nonce", { action: "sign_presentation", audience: "a" }],
      ["cre bad", { action: "generate_proof", credential_response_encryption: { alg: 1 } }],
      ["aux not objects", { action: "generate_proof", auxiliary_data_to_issuer: ["x"] }],
      ["td not array", sign({ transaction_data: {} })],
      ["td entry type", sign({ response_mode: "x", transaction_data: [entry({ type: 5 })] })],
      ["td entry creds", sign({ response_mode: "x", transaction_data: [entry({ credential_ids: "pay" })] })],
      ["td alg empty array", sign({ response_mode: "x", transaction_data: [entry({ transaction_data_hashes_alg: [] })] })],
      ["td alg empty string", sign({ response_mode: "x", transaction_data: [entry({ transaction_data_hashes_alg: "" })] })],
      ["td disagrees with raw", sign({ response_mode: "x", transaction_data: [entry({ type: "urn:other" })] })],
      ["td without response_mode", sign({ transaction_data: [entry()] })],
    ];
    for (const [name, c] of cases) expect(code(() => parseSignSubFlowParams(c)), name).toBe(-32602);
  });

  it("answers -31005 unsupported transaction_data for an entry without raw", () => {
    for (const e of [{ type: "t", credential_ids: ["a"] }, entry({ raw: "" })]) {
      try {
        parseSignSubFlowParams(sign({ response_mode: "x", transaction_data: [e] }));
        throw new Error("not refused");
      } catch (err) {
        expect((err as WMPError).code).toBe(-31005);
        expect((err as WMPError).data).toEqual({ unsupported: "transaction_data" });
      }
    }
  });

  it("accepts a bare-string transaction_data_hashes_alg", () => {
    const r = enc({ type: "t", credential_ids: ["a"], transaction_data_hashes_alg: ["sha-256"] });
    const e = { raw: r, type: "t", credential_ids: ["a"], transaction_data_hashes_alg: "sha-256" };
    expect(() => parseSignSubFlowParams(sign({ response_mode: "x", transaction_data: [e] }))).not.toThrow();
  });
});

describe("parseMatchStartParams", () => {
  it("validates parent_flow_id and dcql_query", () => {
    expect(parseMatchStartParams({ parent_flow_id: "p", dcql_query: { credentials: [] } }).parent_flow_id).toBe("p");
    for (const b of [{}, { parent_flow_id: "p" }, { dcql_query: {} }, { parent_flow_id: "p", dcql_query: [] }, { parent_flow_id: "p", dcql_query: {}, verified_request: 1 }, null]) {
      expect(code(() => parseMatchStartParams(b))).toBe(-32602);
    }
  });
});

describe("transaction_data capability", () => {
  it("offersTransactionData reads what the peer offered", () => {
    expect(offersTransactionData({ transaction_data: { versions: [1] } })).toBe(true);
    expect(offersTransactionData({ transaction_data: { versions: [2] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [2, 1] } })).toBe(true);
    expect(offersTransactionData({ transaction_data: { versions: "1" } })).toBe(false);
    expect(offersTransactionData({ transaction_data: {} })).toBe(false);
    expect(offersTransactionData({ transaction_data: "x" })).toBe(false);
    expect(offersTransactionData({})).toBe(false);
    expect(offersTransactionData(undefined)).toBe(false);
    // malformed descriptors are not offers, whatever else they say
    expect(offersTransactionData({ transaction_data: { versions: [1, "2"] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [1], hash_algs: 42 } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [1], hash_algs: ["sha-256", 7] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [1], hash_algs: [""] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [1.5, 1] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [0, 1] } })).toBe(false);
    expect(offersTransactionData({ transaction_data: [1] })).toBe(false);
    expect(offersTransactionData({ transaction_data: null as never })).toBe(false);
    expect(offersTransactionData({ transaction_data: { versions: [1], hash_algs: ["sha-256"] } })).toBe(true);
    expect(offersTransactionData({ transaction_data: { versions: [2] } }, 2)).toBe(true);
    expect(CAPABILITY_TRANSACTION_DATA).toBe("transaction_data");
  });

  it("unsupported data/error: unsupported always present, redirect_uri additive", () => {
    expect(transactionDataUnsupportedData()).toEqual({ unsupported: "transaction_data" });
    expect(transactionDataUnsupportedData("https://v.example/cb?x")).toEqual({ unsupported: "transaction_data", redirect_uri: "https://v.example/cb?x" });
    const e = transactionDataUnsupportedError("https://v.example/cb");
    expect(e.code).toBe(-31005);
    expect(e.data).toEqual({ unsupported: "transaction_data", redirect_uri: "https://v.example/cb" });
  });
});

describe("answer helpers", () => {
  const wmp = { version: "0.1", session_id: "ses-1", sender: "x509:san:dns:orch" };
  it("completeSubFlow sends flow.complete with only version and session", async () => {
    const notify = vi.fn(async () => {});
    await completeSubFlow({ notify }, wmp, "f1", { proof_jwt: "eyJ" });
    expect(notify).toHaveBeenCalledWith("wmp.flow.complete", { wmp: { version: "0.1", session_id: "ses-1" }, flow_id: "f1", result: { proof_jwt: "eyJ" } });
  });
  it("completeSubFlow does not send a non-conforming result", async () => {
    const notify = vi.fn(async () => {});
    await expect(completeSubFlow({ notify }, wmp, "f1", { credential_count: 1, transaction_id: "t" })).rejects.toBeInstanceOf(CompletionResultError);
    expect(notify).not.toHaveBeenCalled();
  });
  it("rejectSubFlow is -31006 with data.reason rejected", async () => {
    const notify = vi.fn(async () => {});
    await rejectSubFlow({ notify }, wmp, "f1");
    expect(notify).toHaveBeenCalledWith("wmp.flow.error", { wmp: { version: "0.1", session_id: "ses-1" }, flow_id: "f1", code: -31006, message: "declined", data: { reason: "rejected" } });
  });
  it("unsupportedTransactionData is -31005 with data.unsupported", async () => {
    const notify = vi.fn(async () => {});
    await unsupportedTransactionData({ notify }, wmp, "f1");
    expect(notify).toHaveBeenCalledWith("wmp.flow.error", { wmp: { version: "0.1", session_id: "ses-1" }, flow_id: "f1", code: -31005, message: "Capability not supported", data: { unsupported: "transaction_data" } });
  });
});

// ---------------------------------------------------------------------------
// The profile end to end over a Peer
// ---------------------------------------------------------------------------

const settle = (ms = 30) => new Promise((r) => setTimeout(r, ms));

function start(type: string, flowId: string, params: unknown) {
  return { jsonrpc: "2.0" as const, id: `s-${flowId}`, method: "wmp.flow.start", params: { wmp: { version: "0.1", session_id: "ses-1" }, flow_type: type, flow_id: flowId, params } };
}

async function walletPeer(config: ConstructorParameters<typeof OpenID4xProfile>[0], caps: Record<string, unknown> = { oid4vp: {}, oid4vci: {} }) {
  const t = new MockTransport();
  const peer = new Peer(t, {
    handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: caps, security: { mode: "tls" } }) },
  });
  peer.use(new OpenID4xProfile(config));
  t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  await settle();
  t.sent.length = 0;
  return { t, peer };
}

describe("OpenID4xProfile as sign responder", () => {
  it("answers the start, then lets the callback complete the sub-flow (after the response)", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: async (flow) => {
        expect(flow.params.action).toBe("generate_proof");
        await flow.complete({ proof_jwt: "eyJ" });
      },
    });
    t.receive(start("sign", "flow-1-sign", { action: "generate_proof", nonce: "n", audience: "a", proof_type: "jwt", parent_flow_id: "flow-1" }));
    await settle();
    expect((t.sent[0] as Response).result).toMatchObject({ flow_id: "flow-1-sign", flow_type: "sign" });
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { flow_id: "flow-1-sign", result: { proof_jwt: "eyJ" } } });
  });

  it("refuses a malformed start with -32602 and never calls the callback", async () => {
    const onSign = vi.fn();
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign });
    t.receive(start("sign", "f", { action: "no-such-action" }));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-32602);
    expect(onSign).not.toHaveBeenCalled();
  });

  it("lets the callback reject the sub-flow", async () => {
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign: (flow) => flow.reject() });
    t.receive(start("sign", "f", sign()));
    await settle();
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.error", params: { code: -31006, data: { reason: "rejected" } } });
  });

  it("ends the sub-flow with a fixed error when the callback throws something unexpected", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: () => {
        throw new Error("secret detail: refresh_token=abc");
      },
    });
    t.receive(start("sign", "f", sign()));
    await settle();
    const err = t.sent[1] as { method: string; params: { code: number; message: string } };
    expect(err.method).toBe("wmp.flow.error");
    expect(err.params.code).toBe(-31006);
    expect(JSON.stringify(err)).not.toContain("secret");
    expect(JSON.stringify(err)).not.toContain("refresh_token");
  });

  it("passes a WMPError the callback throws through", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: () => {
        throw new WMPError(ErrorCode.InvalidParams, "bad nonce", { reason: "nonce" });
      },
    });
    t.receive(start("sign", "f", sign()));
    await settle();
    expect(t.sent[1]).toMatchObject({ params: { code: -32602, message: "bad nonce", data: { reason: "nonce" } } });
  });

  it("refuses transaction_data with -31005 unless the capability is configured", async () => {
    const onSign = vi.fn();
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign });
    t.receive(start("sign", "f", sign({ response_mode: "direct_post", transaction_data: [entry()] })));
    await settle();
    expect((t.sent[0] as Response).error).toEqual({ code: -31005, message: "Capability not supported", data: { unsupported: "transaction_data" } });
    expect(onSign).not.toHaveBeenCalled();

    const onSign2 = vi.fn();
    const w2 = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, transactionData: { versions: [1], hash_algs: ["sha-256"] }, onSign: onSign2 });
    w2.t.receive(start("sign", "f", sign({ response_mode: "direct_post", transaction_data: [entry()] })));
    await settle();
    expect((w2.t.sent[0] as Response).error).toBeUndefined();
    expect(onSign2).toHaveBeenCalled();
  });

  it("does not handle sign without onSign: -31005", async () => {
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] } });
    t.receive(start("sign", "f", sign()));
    await settle();
    expect((t.sent[0] as Response).error).toEqual({ code: -31005, message: "Capability not supported", data: { unsupported: "sign" } });
  });
});

describe("OpenID4xProfile as match responder", () => {
  const q = { credentials: [{ id: "pid", format: "dc+sd-jwt" }] };

  it("completes with the closed result", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onMatch: (p) => {
        expect(p.dcql_query).toEqual(q);
        return { satisfiable: true, satisfiable_query_ids: ["pid"], selection_handle: H };
      },
    });
    t.receive(start("match", "flow-vp-1-match", { parent_flow_id: "flow-vp-1", dcql_query: q }));
    await settle();
    expect((t.sent[0] as Response).result).toMatchObject({ flow_type: "match" });
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { flow_id: "flow-vp-1-match", result: { satisfiable: true, satisfiable_query_ids: ["pid"], selection_handle: H } } });
  });

  it("never sends credential data: a result with extra members becomes satisfiable=false, code error", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onMatch: () => ({ satisfiable: true, claims: { family_name: "Svensson" } }) as never,
    });
    t.receive(start("match", "m", { parent_flow_id: "p", dcql_query: q }));
    await settle();
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { result: { satisfiable: false, code: "error" } } });
    expect(JSON.stringify(t.sent)).not.toContain("Svensson");
  });

  it("an id that is not in the query becomes code error", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onMatch: () => ({ satisfiable: true, satisfiable_query_ids: ["other"] }),
    });
    t.receive(start("match", "m", { parent_flow_id: "p", dcql_query: q }));
    await settle();
    expect(t.sent[1]).toMatchObject({ params: { result: { satisfiable: false, code: "error" } } });
  });

  it("a throw answers code error without the cause; a rejection is -31006 rejected", async () => {
    const a = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onMatch: () => {
        throw new Error("secret detail");
      },
    });
    a.t.receive(start("match", "m", { parent_flow_id: "p", dcql_query: q }));
    await settle();
    expect(a.t.sent[1]).toMatchObject({ params: { result: { satisfiable: false, code: "error" } } });
    expect(JSON.stringify(a.t.sent)).not.toContain("secret");

    const b = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onMatch: () => {
        throw new SubFlowRejectedError();
      },
    });
    b.t.receive(start("match", "m", { parent_flow_id: "p", dcql_query: q }));
    await settle();
    expect(b.t.sent[1]).toMatchObject({ method: "wmp.flow.error", params: { code: -31006, data: { reason: "rejected" } } });
  });

  it("is gated on the oid4vp capability and needs oid4vp configured", async () => {
    const onMatch = vi.fn();
    const w = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onMatch }, { oid4vci: {} });
    w.t.receive(start("match", "m", { parent_flow_id: "p", dcql_query: q }));
    await settle();
    expect((w.t.sent[0] as Response).error).toEqual({ code: -31005, message: "Capability not supported", data: { unsupported: "match", capability: "oid4vp" } });
    expect(onMatch).not.toHaveBeenCalled();
    expect(new OpenID4xProfile({ onMatch }).flowTypes()).not.toContain("match");
  });

  it("refuses a malformed start with -32602", async () => {
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onMatch: () => ({ satisfiable: true }) });
    t.receive(start("match", "m", { parent_flow_id: "p" }));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-32602);
  });
});

describe("OpenID4xProfile capability descriptors", () => {
  it("emits each configured capability with [] for empty required lists", () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: ["authorization_code"] } as never,
      oid4vp: { supported_response_modes: ["direct_post"], supported_formats: ["dc+sd-jwt"] },
      transactionData: { versions: [1], hash_algs: ["sha-256"] },
    });
    expect(p.capabilityDescriptors()).toEqual({
      oid4vci: { supported_grants: ["authorization_code"], supported_formats: [] },
      oid4vp: { supported_response_modes: ["direct_post"], supported_formats: ["dc+sd-jwt"] },
      transaction_data: { versions: [1], hash_algs: ["sha-256"] },
    });
    expect(p.capabilities()).toEqual(["oid4vci", "oid4vp", "transaction_data"]);
    expect(new OpenID4xProfile({}).capabilityDescriptors()).toEqual({});
  });

  it("refuses a transaction_data descriptor without versions", () => {
    expect(() => new OpenID4xProfile({ transactionData: { versions: [] } }).capabilityDescriptors()).toThrow();
  });
});

describe("the sub-flow's terminal notification never overtakes the flow.start response", () => {
  it("waits for the response send to complete, however slow it is", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vp: {}, oid4vci: {} }, security: { mode: "tls" } }) },
    });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign: (flow) => flow.complete({ proof_jwt: "eyJ" }) }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();

    // From here the response to flow.start is slow, as an HTTP POST can be.
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (msg) => {
      const m = msg as { id?: string; method?: string };
      if (m.id !== undefined && m.method === undefined) await gate;
      order.push(m.method ?? "response");
      await realSend(msg);
    };
    t.receive(start("sign", "flow-9", sign({ action: "generate_proof", nonce: "n", audience: "a" })));
    await settle(60);
    expect(order).toEqual([]); // not even the completion went out while the response is pending
    release();
    await settle(60);
    expect(order).toEqual(["response", "wmp.flow.complete"]);
  });

  it("does not run the continuation when the start is answered with an error", async () => {
    const onSign = vi.fn();
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign });
    t.receive(start("sign", "f", { action: "nope" }));
    await settle(60);
    expect(onSign).not.toHaveBeenCalled();
  });
});

describe("decrypt_credential_response results carry control members only", () => {
  it("validateSignResult", () => {
    for (const ok of [{ credential_count: 1 }, { transaction_id: "t" }, { transaction_id: "t", interval: 5 }, { error: { code: "x" } }]) {
      expect(() => validateSignResult("decrypt_credential_response", ok), JSON.stringify(ok)).not.toThrow();
    }
    for (const bad of [
      {},
      { credentials: [{ credential: "TOP-SECRET" }] },
      { credentials: [{ format: "dc+sd-jwt" }] },
      { credential_metadata: { display: [] } },
      { credential_count: 1, credentials: [] },
      { credential_count: 1, extra: 1 },
      { proof_jwt: "eyJ" },
    ]) {
      expect(() => validateSignResult("decrypt_credential_response", bad), JSON.stringify(bad)).toThrow(CompletionResultError);
    }
    // other actions keep only the general rules
    expect(() => validateSignResult("generate_proof", { proof_jwt: "eyJ", credentials: [] })).not.toThrow();
  });

  it("the profile never sends decrypted credentials to the orchestrator", async () => {
    const { t } = await walletPeer({
      oid4vci: { supported_grants: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ credentials: [{ format: "dc+sd-jwt", credential: "TOP-SECRET-CREDENTIAL" }] }),
    });
    t.receive(start("sign", "dec-1", { action: "decrypt_credential_response", parent_flow_id: "p", jwe: "a.b.c.d.e", deferred: false }));
    await settle();
    expect(JSON.stringify(t.sent)).not.toContain("TOP-SECRET");
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.error", params: { code: -31006 } }); // the sub-flow fails, fixed message
  });

  it("the profile sends the control result", async () => {
    const { t } = await walletPeer({
      oid4vci: { supported_grants: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ credential_count: 2 }),
    });
    t.receive(start("sign", "dec-1", { action: "decrypt_credential_response", parent_flow_id: "p", jwe: "a.b.c.d.e" }));
    await settle();
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { result: { credential_count: 2 } } });
  });
});

describe("flow.start in notification form", () => {
  it("is dropped: nothing runs and nothing is queued for a later start", async () => {
    const onSign = vi.fn();
    const { t } = await walletPeer({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign });
    const note = { jsonrpc: "2.0" as const, method: "wmp.flow.start", params: { wmp: { version: "0.1", session_id: "ses-1" }, flow_type: "sign", flow_id: "dup", params: sign() } };
    t.receive(note as never);
    await settle(60);
    expect(onSign).not.toHaveBeenCalled();
    expect(t.sent).toHaveLength(0);
    // a real start under the same id runs the continuation exactly once
    t.receive(start("sign", "dup", sign()));
    await settle(60);
    expect(onSign).toHaveBeenCalledTimes(1);
  });
});

describe("continuations belong to their own request", () => {
  it("a duplicate start rejected while the original's response is still being sent does not discard the original's continuation", async () => {
    const onSign = vi.fn(async (flow: { complete(r: unknown): Promise<void> }) => {
      await flow.complete({ vp_token: "eyJ" });
    });
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }) },
    });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign: onSign as never }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    t.sent.length = 0;

    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (msg) => {
      const m = msg as { id?: string; method?: string };
      if (m.id === "s-dup-1") await gate; // only the ORIGINAL's response is slow
      await realSend(msg);
    };
    t.receive({ ...start("sign", "dup", sign()), id: "s-dup-1" });
    await settle(30);
    t.receive({ ...start("sign", "dup", sign()), id: "s-dup-2" }); // a duplicate while the first response is in flight
    await settle(30);
    expect(t.sent.find((m) => (m as { id?: string }).id === "s-dup-2")).toMatchObject({ error: { code: -32602 } });
    release();
    await settle(60);
    expect(onSign).toHaveBeenCalledTimes(1);
    expect(t.sent.some((m) => (m as { method?: string }).method === "wmp.flow.complete")).toBe(true);
  });
});

describe("finished sub-flows free their slot", () => {
  it("4100 sequential sign sub-flows, completed or failed through the profile, never hit the active-flow limit", async () => {
    let n = 0;
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: (flow) => (n++ % 2 ? flow.reject() : flow.complete({ proof_jwt: "eyJ" })),
    });
    for (let i = 0; i < 4100; i++) {
      t.receive({ ...start("sign", `sf-${i}`, sign({ action: "generate_proof" })), id: `r${i}` });
      await new Promise((r) => setImmediate(r));
    }
    await settle(50);
    const errors = t.sent.filter((m) => (m as Response).error);
    expect(errors).toHaveLength(0);
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.complete" || (m as { method?: string }).method === "wmp.flow.error")).toHaveLength(4100);
  }, 60_000);
});

describe("a sub-flow ends once (round 4)", () => {
  const mk = () => {
    const notify = vi.fn(async () => {});
    const flow = new SignFlow({ notify }, { version: "0.1", session_id: "ses-1" }, "f1", { action: "generate_proof" } as never);
    return { notify, flow };
  };

  it("a second terminal is refused", async () => {
    const { notify, flow } = mk();
    await flow.complete({ proof_jwt: "eyJ" });
    expect(flow.ended).toBe(true);
    await expect(flow.complete({ proof_jwt: "x" })).rejects.toThrow(/already ended/);
    await expect(flow.reject()).rejects.toThrow(/already ended/);
    await expect(flow.fail(-31006, "x")).rejects.toThrow(/already ended/);
    await expect(flow.unsupportedTransactionData()).rejects.toThrow(/already ended/);
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it("two concurrent terminals: one is sent", async () => {
    const { notify, flow } = mk();
    const results = await Promise.allSettled([flow.complete({ proof_jwt: "a" }), flow.reject()]);
    expect(results.filter((r) => r.status === "fulfilled")).toHaveLength(1);
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it("a result that fails validation, or a failed send, does not end the sub-flow", async () => {
    const { notify, flow } = mk();
    await expect(flow.complete({ credential_count: 1, transaction_id: "t" })).rejects.toBeInstanceOf(CompletionResultError);
    expect(flow.ended).toBe(false);
    notify.mockRejectedValueOnce(new Error("transport down"));
    await expect(flow.reject()).rejects.toThrow("transport down");
    expect(flow.ended).toBe(false);
    await flow.fail(-31006, "x"); // still possible
    expect(flow.ended).toBe(true);
  });

  it("the profile sends no second terminal when the callback ended the sub-flow and then threw", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: async (flow) => {
        await flow.complete({ proof_jwt: "eyJ" });
        throw new Error("cleanup failed");
      },
    });
    t.receive(start("sign", "once", sign({ action: "generate_proof" })));
    await settle(60);
    const terminals = t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.complete" || (m as { method?: string }).method === "wmp.flow.error");
    expect(terminals).toHaveLength(1);
    expect(terminals[0]).toMatchObject({ method: "wmp.flow.complete" });
  });
});

describe("sign_presentation results follow the response mode (profile 7.7)", () => {
  const jwe = "aaaa.x.bbbb.cccc.dddd";
  it("an encrypted mode needs response_jwe and never carries a vp_token", () => {
    for (const mode of ["direct_post.jwt", "dc_api.jwt"]) {
      expect(() => validateSignResult("sign_presentation", { response_jwe: jwe }, mode), mode).not.toThrow();
      expect(() => validateSignResult("sign_presentation", { vp_token: "PLAINTEXT-VP" }, mode), mode).toThrow(CompletionResultError);
      expect(() => validateSignResult("sign_presentation", { vp_token: "x", response_jwe: jwe }, mode), mode).toThrow(CompletionResultError);
      expect(() => validateSignResult("sign_presentation", {}, mode), mode).toThrow(CompletionResultError);
    }
  });

  it("a successful result in a plaintext or unspecified mode must carry the vp_token", () => {
    for (const mode of ["direct_post", "dc_api", undefined]) {
      expect(() => validateSignResult("sign_presentation", {}, mode as never), String(mode)).toThrow(CompletionResultError);
      expect(() => validateSignResult("sign_presentation", { proof_jwt: "eyJ" }, mode as never), String(mode)).toThrow(CompletionResultError);
      expect(() => validateSignResult("sign_presentation", { vp_token: ["a", "b"] }, mode as never), String(mode)).not.toThrow();
      expect(() => validateSignResult("sign_presentation", { error: { code: "access_denied" } }, mode as never), String(mode)).not.toThrow(); // error-only results stay valid
    }
  });

  it("the profile sends no presentation-less success", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ proof_jwt: "eyJ" }),
    });
    t.receive(start("sign", "nopres", sign({ response_mode: "direct_post" })));
    await settle(60);
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.error", params: { code: -31006 } });
    expect(t.sent.some((m) => (m as { method?: string }).method === "wmp.flow.complete")).toBe(false);
  });

  it("a plaintext or unspecified mode takes a vp_token and refuses a JWE", () => {
    for (const mode of ["direct_post", "dc_api", undefined]) {
      expect(() => validateSignResult("sign_presentation", { vp_token: "x" }, mode as never), String(mode)).not.toThrow();
      expect(() => validateSignResult("sign_presentation", { response_jwe: jwe }, mode as never), String(mode)).toThrow(CompletionResultError);
    }
  });

  it("the profile never sends a plaintext vp_token for direct_post.jwt", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ vp_token: "PLAINTEXT-VP-TOKEN" }),
    });
    t.receive(start("sign", "enc", sign({ response_mode: "direct_post.jwt" })));
    await settle(60);
    expect(JSON.stringify(t.sent)).not.toContain("PLAINTEXT-VP-TOKEN");
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.error", params: { code: -31006 } });
  });

  it("the profile sends the response_jwe for direct_post.jwt", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ response_jwe: jwe }),
    });
    t.receive(start("sign", "enc", sign({ response_mode: "direct_post.jwt" })));
    await settle(60);
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { result: { response_jwe: jwe } } });
  });
});

describe("sparse arrays are not selections (round 4)", () => {
  it("validate and build refuse holes", async () => {
    const { validateSelectCredentialsParams, buildSelectCredentials, ActionParamsError } = await import("../src/consent.js");
    // eslint-disable-next-line no-sparse-arrays
    expect(() => validateSelectCredentialsParams({ consent: true, selections: new Array(1) })).toThrow(ActionParamsError);
    const holey: unknown[] = [{ query_id: "pid", selection_handle: H }];
    holey[2] = { query_id: "mdl", selection_handle: H }; // index 1 is a hole
    expect(() => validateSelectCredentialsParams({ consent: true, selections: holey })).toThrow(ActionParamsError);
    expect(() => buildSelectCredentials({ consent: true, queryIds: new Array(1), selectionHandle: H })).toThrow(ActionParamsError);
    expect(() => buildSelectCredentials({ consent: true, queryIds: ["pid"], selectionHandle: H })).not.toThrow();
  });
});

describe("a start whose response cannot be delivered leaves nothing behind (round 4)", () => {
  it("rolls the flow back and never runs the continuation; the id can be started again", async () => {
    const onSign = vi.fn(async (flow: { complete(r: unknown): Promise<void> }) => {
      await flow.complete({ proof_jwt: "eyJ" });
    });
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }) } });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign: onSign as never }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    t.sent.length = 0;
    const realSend = t.send.bind(t);
    let failed = 0;
    t.send = async (msg) => {
      const m = msg as { id?: string; result?: unknown };
      if (m.id === "s-flaky" && m.result !== undefined && failed++ === 0) throw new Error("POST failed"); // the first response send fails
      await realSend(msg);
    };
    t.receive(start("sign", "flaky", sign({ action: "generate_proof" })));
    await settle(60);
    expect(onSign).not.toHaveBeenCalled(); // the continuation never ran
    expect(t.sent.find((m) => (m as { id?: string }).id === "s-flaky")).toMatchObject({ error: expect.anything() }); // the failure was reported
    // the same id is free again: not a duplicate
    t.receive({ ...start("sign", "flaky", sign({ action: "generate_proof" })), id: "s-flaky-2" });
    await settle(60);
    expect(t.sent.find((m) => (m as { id?: string }).id === "s-flaky-2")).toMatchObject({ result: expect.anything() });
    expect(onSign).toHaveBeenCalledTimes(1);
  });

  it("repeated delivery failures do not exhaust the active-flow limit", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }) } });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign: () => {} }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    const realSend = t.send.bind(t);
    const seen = new Set<string>();
    t.send = async (msg) => {
      const m = msg as { id?: string; result?: unknown };
      if (m.id && m.result !== undefined && m.id.startsWith("r") && !seen.has(m.id)) {
        seen.add(m.id);
        throw new Error("POST failed");
      }
      await realSend(msg);
    };
    for (let i = 0; i < 4100; i++) {
      t.receive({ ...start("sign", `fl-${i}`, sign({ action: "generate_proof" })), id: `r${i}` });
      await new Promise((r) => setImmediate(r));
    }
    await settle(50);
    expect(t.sent.filter((m) => (m as Response).error?.code === -31007)).toHaveLength(0);
  }, 60_000);
});

describe("work is bound to its flow generation (round 5)", () => {
  const cancelReq = (flowId: string) => ({ jsonrpc: "2.0" as const, id: `c-${flowId}`, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flowId } });

  async function setupWallet(onSign: (flow: SignFlow) => void | Promise<void>, onMatch?: never) {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }),
      },
    });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onSign, ...(onMatch ? { onMatch } : {}) }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    t.sent.length = 0;
    return { t, peer };
  }

  it("a cancelled flow's queued callback does not run once the id was started again", async () => {
    const seen: string[] = [];
    const { t } = await setupWallet((flow) => {
      seen.push(String(flow.params.nonce));
      return flow.complete({ proof_jwt: `for-${String(flow.params.nonce)}` });
    });
    // the first start's response is slow, so its continuation is still queued
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (msg) => {
      if ((msg as { id?: string }).id === "s-1") await gate;
      await realSend(msg);
    };
    t.receive({ ...start("sign", "x", sign({ action: "generate_proof", nonce: "OLD" })), id: "s-1" });
    await settle(30);
    t.receive(cancelReq("x")); // the flow is cancelled: its id is free
    await settle(30);
    t.receive({ ...start("sign", "x", sign({ action: "generate_proof", nonce: "NEW" })), id: "s-2" });
    await settle(30);
    release(); // now the first response goes out and its continuation would run
    await settle(80);
    expect(seen).toEqual(["NEW"]); // the stale callback never ran
    const completes = t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.complete");
    expect(completes).toHaveLength(1);
    expect(JSON.stringify(completes[0])).toContain("for-NEW");
  });

  it("a late terminal from a stale sub-flow is refused and leaves the replacement's record alone", async () => {
    const flows: SignFlow[] = [];
    const { t, peer } = await setupWallet((flow) => {
      flows.push(flow); // answered later, by the test
    });
    t.receive(start("sign", "x", sign({ action: "generate_proof", nonce: "OLD" })));
    await settle(40);
    t.receive(cancelReq("x"));
    await settle(30);
    t.receive({ ...start("sign", "x", sign({ action: "generate_proof", nonce: "NEW" })), id: "s-new" });
    await settle(40);
    expect(flows).toHaveLength(2);
    t.sent.length = 0;
    await expect(flows[0].complete({ proof_jwt: "stale" })).rejects.toThrow(/no longer active/);
    await expect(flows[0].reject()).rejects.toThrow(/no longer active/);
    expect(t.sent).toHaveLength(0); // nothing reached the orchestrator
    expect(peer.flowGeneration("x")).toBeDefined(); // the replacement is still registered
    await flows[1].complete({ proof_jwt: "fresh" }); // and can finish normally
    expect(t.sent).toHaveLength(1);
    expect(peer.flowGeneration("x")).toBeUndefined();
  });

  it("a cancelled match flow's callback does not run", async () => {
    const onMatch = vi.fn(() => ({ satisfiable: true }));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vp: {} }, security: { mode: "tls" } }),
        onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }),
      },
    });
    peer.use(new OpenID4xProfile({ oid4vp: { supported_response_modes: [], supported_formats: [] }, onMatch }));
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (msg) => {
      if ((msg as { id?: string }).id === "s-m") await gate;
      await realSend(msg);
    };
    t.receive({ jsonrpc: "2.0", id: "s-m", method: "wmp.flow.start", params: { wmp: { version: "0.1", session_id: "ses-1" }, flow_type: "match", flow_id: "m", params: { parent_flow_id: "p", dcql_query: { credentials: [{ id: "pid" }] } } } });
    await settle(30);
    t.receive(cancelReq("m"));
    await settle(30);
    release();
    await settle(60);
    expect(onMatch).not.toHaveBeenCalled();
    expect(t.sent.some((m) => (m as { method?: string }).method === "wmp.flow.complete")).toBe(false);
  });

  it("Peer.notifyFlow refuses another generation and only retires its own", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }) } });
    t.receive({ jsonrpc: "2.0", id: "a", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f", params: {} } });
    await settle();
    const gen1 = peer.flowGeneration("f");
    expect(gen1).toBeDefined();
    t.receive(cancelReq("f"));
    await settle();
    expect(peer.flowGeneration("f")).toBeUndefined();
    t.receive({ jsonrpc: "2.0", id: "b", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f", params: {} } });
    await settle();
    const gen2 = peer.flowGeneration("f");
    expect(gen2).toBeDefined();
    expect(gen2).not.toBe(gen1);
    await expect(peer.notifyFlow(gen1, "wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "f", result: {} })).rejects.toThrow();
    expect(peer.flowGeneration("f")).toBe(gen2);
    await peer.notifyFlow(gen2, "wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "f", result: {} });
    expect(peer.flowGeneration("f")).toBeUndefined();
  });
});

describe("a missing record authorizes nothing (round 6)", () => {
  it("notifyFlow without a generation, or for an inactive flow, sends nothing", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    await expect(peer.notifyFlow(undefined, "wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "never", result: {} })).rejects.toThrow(/no longer active/);
    await expect(peer.notifyFlow(undefined, "wmp.flow.complete", { wmp: { version: "0.1" }, result: {} })).rejects.toThrow(/no longer active/);
    await expect(peer.notifyFlow({}, "wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "never", result: {} })).rejects.toThrow(/no longer active/);
    expect(t.sent).toHaveLength(0);
  });

  it("a notifier created after the flow ended cannot send, and reports not current", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }),
        onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }),
      },
    });
    t.receive({ jsonrpc: "2.0", id: "a", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f", params: {} } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: "f" } });
    await settle();
    t.sent.length = 0;
    const late = boundNotifier(peer, "f"); // made after the flow ended
    expect(late.current()).toBe(false);
    await expect(late.notify("wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "f", result: {} })).rejects.toThrow(/no longer active/);
    expect(t.sent).toHaveLength(0);
  });
});

describe("retiring after a slow send (round 5)", () => {
  it("a terminal still being sent does not retire a replacement started meanwhile", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }) } });
    const startReq = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f", params: {} } });
    t.receive(startReq("a"));
    await settle();
    const gen1 = peer.flowGeneration("f");
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (m) => {
      if ((m as { method?: string }).method === "wmp.flow.complete") await gate;
      await realSend(m);
    };
    const sending = peer.notifyFlow(gen1, "wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: "f", result: {} });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: "f" } });
    await settle();
    t.receive(startReq("b")); // a replacement under the same id
    await settle();
    const gen2 = peer.flowGeneration("f");
    expect(gen2).toBeDefined();
    release();
    await sending;
    expect(peer.flowGeneration("f")).toBe(gen2); // not retired by the old generation's send
  });
});

describe("error results in encrypted response modes (round 5)", () => {
  const jwe = "aaaa.x.bbbb.cccc.dddd";
  it("a refusal needs no response_jwe, in any mode, and carries no vp_token or JWE", () => {
    for (const mode of ["direct_post.jwt", "dc_api.jwt", "direct_post", undefined]) {
      expect(() => validateSignResult("sign_presentation", { error: { code: "access_denied" } }, mode as never), String(mode)).not.toThrow();
      expect(() => validateSignResult("sign_presentation", { error: { code: "x" }, response_jwe: jwe }, mode as never), String(mode)).toThrow(CompletionResultError);
      expect(() => validateSignResult("sign_presentation", { error: { code: "x" }, vp_token: "PLAIN" }, mode as never), String(mode)).toThrow(CompletionResultError);
    }
  });

  it("the profile can report a refusal in direct_post.jwt (not replaced by 'Sign failed')", async () => {
    const { t } = await walletPeer({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onSign: (flow) => flow.complete({ error: { code: "access_denied" } }),
    });
    t.receive(start("sign", "enc-err", sign({ response_mode: "direct_post.jwt" })));
    await settle(60);
    expect(t.sent[1]).toMatchObject({ method: "wmp.flow.complete", params: { result: { error: { code: "access_denied" } } } });
  });
});
