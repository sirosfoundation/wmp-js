import { describe, it, expect, vi } from "vitest";
import {
  CompletionResultError,
  DEFAULT_SECRET_MEMBERS,
  REPLAY_SECRET_MEMBERS,
  redactedMembers,
  splitReplaySecrets,
  validateCompletionResult,
  validateMatchResult,
} from "../src/completion.js";
import { Peer } from "../src/peer.js";
import { ErrorCode } from "../src/types.js";
import { WMPError, type Response } from "../src/jsonrpc.js";
import { MockTransport } from "./mock-transport.js";

const JWE = "aaaa.x.bbbb.cccc.dddd"; // five base64url segments
const HANDLE = "Zm9yLXRoZS13YWxsZXQtb25seQ";

function refused(result: unknown, secretMembers?: readonly string[]): string {
  try {
    validateCompletionResult(result, secretMembers);
  } catch (e) {
    expect(e).toBeInstanceOf(CompletionResultError);
    return (e as Error).message;
  }
  return "";
}

describe("constants", () => {
  it("expose the secret member sets", () => {
    expect(DEFAULT_SECRET_MEMBERS).toEqual(["auxiliary_data"]);
    expect(REPLAY_SECRET_MEMBERS).toEqual(["dpop_jwk", "dpop_key_id", "refresh_token"]);
  });
});

describe("validateCompletionResult", () => {
  it("accepts conforming results", () => {
    for (const r of [
      {},
      { credentials: [{ format: "dc+sd-jwt", credential: "x" }], credential_metadata: { display: [] }, refresh_token: "r" },
      { credential_response_encrypted: true, credentials: [{ format: "dc+sd-jwt" }] },
      { credential_count: 1 },
      { credential_count: 256 },
      { transaction_id: "t", interval: 0 },
      { response_jwe: JWE },
      { response_jwe: "a..b.c.d" }, // only the encrypted key may be empty
      { redacted_members: ["dpop_jwk", "refresh_token"], credentials: [] },
      { unknown_extension: { anything: 1 } },
    ]) {
      expect(refused(r), JSON.stringify(r)).toBe("");
    }
  });

  it("refuses each rule", () => {
    const bad: [string, unknown][] = [
      ["not object", "str"],
      ["array", []],
      ["null", null],
      ["aux in metadata", { credential_metadata: { auxiliary_data: [] } }],
      ["metadata not object", { credential_metadata: [] }],
      ["encrypted not boolean", { credential_response_encrypted: "true" }],
      ["encrypted + metadata", { credential_response_encrypted: true, credential_metadata: {} }],
      ["encrypted + credential value", { credential_response_encrypted: true, credentials: [{ credential: "x" }] }],
      ["encrypted + credentials not array", { credential_response_encrypted: true, credentials: {} }],
      ["redacted empty", { redacted_members: [] }],
      ["redacted not array", { redacted_members: "refresh_token" }],
      ["redacted metadata", { redacted_members: ["credential_metadata"] }],
      ["redacted duplicate", { redacted_members: ["refresh_token", "refresh_token"] }],
      ["redacted and present", { redacted_members: ["refresh_token"], refresh_token: "r" }],
      ["count and tx", { credential_count: 1, transaction_id: "t" }],
      ["count 0", { credential_count: 0 }],
      ["count 257", { credential_count: 257 }],
      ["count float", { credential_count: 1.5 }],
      ["count string", { credential_count: "1" }],
      ["tx empty", { transaction_id: "" }],
      ["interval alone", { interval: 5 }],
      ["count + interval", { credential_count: 1, interval: 5 }],
      ["negative interval", { transaction_id: "t", interval: -1 }],
      ["count + credentials", { credential_count: 1, credentials: [] }],
      ["tx + metadata", { transaction_id: "t", credential_metadata: {} }],
      ["jwe + vp_token", { response_jwe: JWE, vp_token: "x" }],
      ["jwe 4 segments", { response_jwe: "a.b.c.d" }],
      ["jwe empty segment", { response_jwe: "a.b..d.e" }],
      ["jwe not base64url", { response_jwe: "a.b.c.d.e+" }],
      ["jwe not string", { response_jwe: 5 }],
    ];
    for (const [name, r] of bad) {
      expect(refused(r), name).not.toBe("");
    }
  });

  it("requires redacted_members in alphabetical order", () => {
    expect(refused({ redacted_members: ["dpop_jwk", "dpop_key_id", "refresh_token"] })).toBe("");
    expect(refused({ redacted_members: ["dpop_jwk", "refresh_token"] })).toBe("");
    expect(refused({ redacted_members: ["refresh_token", "dpop_jwk"] })).toContain("alphabetical");
    expect(refused({ redacted_members: ["dpop_key_id", "dpop_jwk"] })).toContain("alphabetical");
    expect(refused({ redacted_members: ["refresh_token", "dpop_jwk", "dpop_key_id"] })).not.toBe("");
  });

  it("honours a caller supplied secret member set", () => {
    expect(refused({ credential_metadata: { my_secret: 1 } })).toBe("");
    expect(refused({ credential_metadata: { my_secret: 1 } }, ["my_secret"])).not.toBe("");
    expect(refused({ credential_metadata: { auxiliary_data: 1 } }, [])).toBe("");
  });

  it("never echoes a member value in the error", () => {
    const msg = refused({ credential_response_encrypted: true, credentials: [{ credential: "TOP-SECRET-VALUE" }], refresh_token: "RT-SECRET" });
    expect(msg).not.toContain("TOP-SECRET-VALUE");
    expect(msg).not.toContain("RT-SECRET");
  });
});

describe("validateMatchResult", () => {
  it("accepts the four members", () => {
    expect(() => validateMatchResult({ satisfiable: true, satisfiable_query_ids: ["pid"], selection_handle: HANDLE }, ["pid"])).not.toThrow();
    expect(() => validateMatchResult({ satisfiable: false, code: "insufficient" })).not.toThrow();
    expect(() => validateMatchResult({ satisfiable: true })).not.toThrow();
    expect(() => validateMatchResult({ satisfiable: true, selection_handle: "A".repeat(22) })).not.toThrow();
  });

  it("refuses everything else", () => {
    const bad: [string, unknown, string[]?][] = [
      ["not object", [] ],
      ["missing satisfiable", {}],
      ["satisfiable string", { satisfiable: "true" }],
      ["extra member", { satisfiable: true, claims: {} }],
      ["extra credential_id", { satisfiable: true, credential_id: "c" }],
      ["code with true", { satisfiable: true, code: "error" }],
      ["no code with false", { satisfiable: false }],
      ["free text code", { satisfiable: false, code: "no credential for you" }],
      ["ids not strings", { satisfiable: true, satisfiable_query_ids: [{ id: "pid" }] }],
      ["ids not array", { satisfiable: true, satisfiable_query_ids: "pid" }],
      ["ids repeated", { satisfiable: true, satisfiable_query_ids: ["pid", "pid"] }],
      ["id not in query", { satisfiable: true, satisfiable_query_ids: ["other"] }, ["pid"]],
      ["short handle", { satisfiable: true, selection_handle: "abc" }],
      ["padded handle", { satisfiable: true, selection_handle: HANDLE + "==" }],
      ["handle bad alphabet", { satisfiable: true, selection_handle: "Zm9yLXRoZS13YWxsZXQ+b25seQ" }],
      ["handle impossible length", { satisfiable: true, selection_handle: "A".repeat(25) }],
      ["handle trailing newline", { satisfiable: true, selection_handle: "A".repeat(24) + "\n" }],
      ["handle not string", { satisfiable: true, selection_handle: 5 }],
    ];
    for (const [name, r, q] of bad) {
      expect(() => validateMatchResult(r, q), name).toThrow(CompletionResultError);
    }
  });

  it("does not accept a handle ending in a newline although $ would (regression for a non-anchored regexp)", () => {
    expect(() => validateMatchResult({ satisfiable: true, selection_handle: "A".repeat(22) + "\n" })).toThrow();
  });
});

describe("redactedMembers", () => {
  it("lists only secret names", () => {
    expect(redactedMembers({ redacted_members: ["refresh_token", "dpop_jwk"] })).toEqual(["refresh_token", "dpop_jwk"]);
    expect(redactedMembers({ redacted_members: ["credential_metadata"] })).toEqual([]);
    expect(redactedMembers({})).toEqual([]);
    expect(redactedMembers(null)).toEqual([]);
  });
});

describe("splitReplaySecrets", () => {
  const complete = (result: string) =>
    `{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"wmp":{"version":"0.1"},"flow_id":"f1","result":${result}}}`;

  it("withholds exactly the secret members and marks them", () => {
    const live = complete('{"credentials":[{"credential":"c"}],"refresh_token":"rt","dpop_jwk":"{\\"d\\":\\"x\\"}","dpop_key_id":"k"}');
    const out = splitReplaySecrets(live);
    expect(out.ok).toBe(true);
    expect(out.live).toBe(live);
    const replay = JSON.parse(out.replay);
    expect(replay.params.result).toEqual({
      credentials: [{ credential: "c" }],
      redacted_members: ["dpop_jwk", "dpop_key_id", "refresh_token"],
    });
    expect(out.replay).not.toContain("rt");
    expect(out.replay).not.toContain("dpop_jwk\":");
  });

  it("keeps verbatim values (escapes, number formatting) of preserved members", () => {
    const live = complete('{"credentials":[{"credential":"a\\u00e9b","n":1.50}],"refresh_token":"rt"}');
    const out = splitReplaySecrets(live);
    expect(out.replay).toContain('"credential":"a\\u00e9b","n":1.50');
  });

  it("leaves a completion with nothing to withhold, and other messages, untouched", () => {
    const plain = complete('{"credentials":[]}');
    expect(splitReplaySecrets(plain)).toEqual({ ok: true, replay: plain });
    const other = '{"jsonrpc":"2.0","method":"wmp.flow.progress","params":{"refresh_token":"rt"}}';
    expect(splitReplaySecrets(other)).toEqual({ ok: true, replay: other });
    const resp = '{"jsonrpc":"2.0","id":1,"result":{"refresh_token":"rt"}}';
    expect(splitReplaySecrets(resp)).toEqual({ ok: true, replay: resp });
  });

  it("recognises a secret member whose name is written with a JSON escape", () => {
    const live = complete('{"refresh\\u005ftoken":"rt-esc"}');
    const out = splitReplaySecrets(live);
    expect(out.ok).toBe(true);
    expect(out.replay).not.toContain("rt-esc");
    expect(JSON.parse(out.replay).params.result).toEqual({ redacted_members: ["refresh_token"] });
  });

  it("refuses (ok=false) what it cannot split safely", () => {
    const cases = [
      complete('{"refresh_token":"a","refresh_token":"b"}'), // duplicate name
      complete('{"refresh_token":"a","refresh\\u005ftoken":"b"}'), // duplicate after decoding
      complete('{"Refresh_Token":"a"}'), // letter-case variant
      complete('{"redacted_members":["refresh_token"],"credentials":[]}'),
      complete('{"redacted_members":["refresh_token"],"refresh_token":"a"}'),
      '{"jsonrpc":"2.0","method":"wmp.flow.complete","params":null,"x":"refresh_token"}',
      '{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"result":"refresh_token"}}',
      '{"jsonrpc":"2.0","method":5,"params":{"refresh_token":"x"}}',
      '["refresh_token"]',
      'not json "refresh_token"',
      complete('{"refresh_to\\u212aen":"a"}'), // Kelvin sign folds to k: a letter-case variant
      '{"jsonrpc":"2.0","method":"wmp.flow.complete","params":{"result":{"refresh_token":"a"}}} trailing',
      '{"Method":"wmp.flow.complete","method":"wmp.flow.progress","params":{"result":{"refresh_token":"a"}}}',
    ];
    cases.forEach((c) => expect(splitReplaySecrets(c).ok, c).toBe(false));
  });

  it("accepts bytes", () => {
    const live = complete('{"refresh_token":"rt"}');
    const out = splitReplaySecrets(new TextEncoder().encode(live));
    expect(out.ok).toBe(true);
    expect(out.replay).not.toContain("rt\"");
  });

  it("produces a replay that validates", () => {
    const out = splitReplaySecrets(complete('{"refresh_token":"rt","dpop_key_id":"k"}'));
    expect(() => validateCompletionResult(JSON.parse(out.replay).params.result)).not.toThrow();
  });
});

describe("Peer refuses non-conforming completions", () => {
  const complete = (result: unknown) => ({
    jsonrpc: "2.0" as const,
    method: "wmp.flow.complete",
    params: { wmp: { version: "0.1" }, flow_id: "f1", result },
  });
  const settle = () => new Promise((r) => setTimeout(r, 10));

  it("does not deliver the completion and ends the flow with -32602", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const onRefusedCompletion = vi.fn();
    new Peer(t, { handler: { onFlowComplete, onFlowError }, onRefusedCompletion });
    t.receive(complete({ credential_response_encrypted: true, credentials: [{ credential: "LEAK" }] }));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
    const err = onFlowError.mock.calls[0][0];
    expect(err.code).toBe(ErrorCode.InvalidParams);
    expect(err.flow_id).toBe("f1");
    expect(JSON.stringify(err)).not.toContain("LEAK");
    expect(onRefusedCompletion).toHaveBeenCalledWith("f1", expect.any(CompletionResultError));
    expect(JSON.stringify(onRefusedCompletion.mock.calls[0][1].message)).not.toContain("LEAK");
  });

  it("delivers a conforming completion, redacted_members and all", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    new Peer(t, { handler: { onFlowComplete } });
    t.receive(complete({ credentials: [], redacted_members: ["refresh_token"] }));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    expect(redactedMembers(onFlowComplete.mock.calls[0][0].result)).toEqual(["refresh_token"]);
  });

  it("can be switched off", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    new Peer(t, { handler: { onFlowComplete }, validateCompletions: false });
    t.receive(complete("whatever"));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });
});

describe("Peer: match flows and validator ordering", () => {
  const settle = () => new Promise((r) => setTimeout(r, 10));
  const complete = (flowId: string, result?: unknown) => ({
    jsonrpc: "2.0" as const,
    method: "wmp.flow.complete",
    params: { wmp: { version: "0.1" }, flow_id: flowId, ...(result === undefined ? {} : { result }) },
  });
  const query = { credentials: [{ id: "pid" }, { id: "mdl" }] };

  async function matchPeer(opts: ConstructorParameters<typeof Peer>[1] = {}) {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const peer = new Peer(t, { ...opts, handler: { onFlowComplete, onFlowError } });
    // the flow starts from this peer, so its type is recorded
    const p = peer.startFlow("match", "m1", { parent_flow_id: "p", dcql_query: query });
    p.catch(() => {});
    return { t, peer, onFlowComplete, onFlowError };
  }

  it("applies the closed match set by the recorded flow type: extra members are refused", async () => {
    const { t, onFlowComplete, onFlowError } = await matchPeer();
    t.receive(complete("m1", { satisfiable: true, claims: { name: "secret" } }));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
    expect(JSON.stringify(onFlowError.mock.calls)).not.toContain("secret");
  });

  it("refuses a match completion with no result, and a query id the query does not have", async () => {
    for (const result of [undefined, { satisfiable: true, satisfiable_query_ids: ["other"] }]) {
      const { t, onFlowComplete, onFlowError } = await matchPeer();
      t.receive(complete("m1", result));
      await settle();
      expect(onFlowComplete).not.toHaveBeenCalled();
      expect(onFlowError).toHaveBeenCalledTimes(1);
    }
  });

  it("delivers a conforming match result", async () => {
    const { t, onFlowComplete } = await matchPeer();
    t.receive(complete("m1", { satisfiable: true, satisfiable_query_ids: ["pid"] }));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("also records the type of an incoming flow.start", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowComplete, onFlowError } });
    t.receive({ jsonrpc: "2.0", id: "s", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "match", flow_id: "m2", params: { dcql_query: query } } });
    await settle();
    t.receive(complete("m2", { satisfiable: true, vct: "urn:eudi:pid:1" }));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a flow that is not a match flow is not held to the match set, and an unknown flow gets the general rules", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    new Peer(t, { handler: { onFlowComplete } });
    t.receive(complete("other", { satisfiable: true, anything: 1 })); // no recorded type: never decided by the members
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("refuses a non-conforming completion even when the generic validator rejects the message", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const onRefusedCompletion = vi.fn();
    new Peer(t, {
      handler: { onFlowComplete, onFlowError },
      onRefusedCompletion,
      validator: { validateMethod: () => [{ path: "", message: "rejected by test validator" }] },
    });
    t.receive(complete("f1", { credential_response_encrypted: true, credentials: [{ credential: "LEAK" }] }));
    await settle();
    expect(onRefusedCompletion).toHaveBeenCalledTimes(1);
    expect(onFlowError).toHaveBeenCalledTimes(1);
    expect(onFlowComplete).not.toHaveBeenCalled();
  });

  it("still drops a conforming completion the validator rejects, and honours authorize", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onRefusedCompletion = vi.fn();
    new Peer(t, { handler: { onFlowComplete }, onRefusedCompletion, validator: { validateMethod: () => [{ path: "", message: "no" }] } });
    t.receive(complete("f1", { credentials: [] }));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onRefusedCompletion).not.toHaveBeenCalled();

    // not authorized: authorization comes first, so nothing is delivered, reported or synthesized
    const t2 = new MockTransport();
    const refused2 = vi.fn();
    const err2 = vi.fn();
    new Peer(t2, { handler: { onFlowError: err2 }, onRefusedCompletion: refused2, authorize: () => false });
    t2.receive(complete("f1", { credential_response_encrypted: true, credentials: [{ credential: "x" }] }));
    await settle();
    expect(refused2).not.toHaveBeenCalled();
    expect(err2).not.toHaveBeenCalled();
  });
});

describe("Peer: flow context bookkeeping", () => {
  const settle = () => new Promise((r) => setTimeout(r, 10));
  const query = { credentials: [{ id: "pid" }] };
  const complete = (flowId: string, result?: unknown, wmp: unknown = { version: "0.1" }) => ({
    jsonrpc: "2.0" as const,
    method: "wmp.flow.complete",
    params: { ...(wmp === null ? {} : { wmp }), flow_id: flowId, ...(result === undefined ? {} : { result }) },
  });
  const start = (id: string, type: string, flowId: string, params: unknown = {}) => ({
    jsonrpc: "2.0" as const,
    id,
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1" }, flow_type: type, flow_id: flowId, params },
  });
  const secret = { satisfiable: true, claims: { name: "secret" } };

  it("a match flow started through call() (as profiles do) is held to the match set", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const peer = new Peer(t, { handler: { onFlowComplete, onFlowError } });
    peer.call("wmp.flow.start", { wmp: { version: "0.1" }, flow_type: "match", flow_id: "m1", params: { parent_flow_id: "p", dcql_query: query } }).catch(() => {});
    t.receive(complete("m1", secret));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a second start under an active flow_id is refused and the first flow's context survives", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => {
          if (p.flow_type === "other") throw new WMPError(ErrorCode.MethodNotFound, "x");
          return { wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type };
        },
        onFlowComplete,
        onFlowError,
      },
    });
    t.receive(start("s1", "match", "m1", { dcql_query: query }));
    await settle();
    t.receive(start("s2", "other", "m1")); // same id, another type
    await settle();
    expect((t.sent[1] as Response).error).toMatchObject({ code: -32602 });
    t.receive(complete("m1", secret)); // still a match flow
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a start that fails leaves no context: the id is free again", async () => {
    const t = new MockTransport();
    let fail = true;
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => {
          if (fail) throw new WMPError(ErrorCode.InvalidParams, "no");
          return { wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type };
        },
      },
    });
    t.receive(start("s1", "match", "m1", { dcql_query: query }));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-32602);
    fail = false;
    t.receive(start("s2", "match", "m1", { dcql_query: query }));
    await settle();
    expect((t.sent[1] as Response).error).toBeUndefined();
  });

  it("an outgoing start the other side refuses leaves no context either", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowComplete: vi.fn() } });
    const p = peer.startFlow("match", "m1", { dcql_query: query });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, error: { code: -31005, message: "x" } });
    await expect(p).rejects.toBeDefined();
    const again = peer.startFlow("match", "m1", { dcql_query: query }); // the id is free
    again.catch(() => {});
    await settle();
    expect(t.sent).toHaveLength(2);
  });

  it("refuses a duplicate active outgoing start and a flow.cancel frees the id", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }) } });
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    await expect(peer.startFlow("sign", "f1", {})).rejects.toMatchObject({ code: -32602 });
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: "f1" } });
    await settle();
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(2);
  });

  it("at capacity a new start is refused instead of evicting an existing flow's context", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    new Peer(t, {
      handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowComplete, onFlowError },
    });
    t.receive(start("m", "match", "match-flow", { dcql_query: query }));
    for (let i = 0; i < 4095; i++) t.receive(start(`s${i}`, "x", `f${i}`));
    await settle();
    t.sent.length = 0;
    t.receive(start("over", "x", "one-too-many"));
    await settle();
    expect((t.sent[0] as Response).error).toMatchObject({ code: -31007 });
    t.receive(complete("match-flow", secret)); // the oldest flow's context is intact
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a completion without wmp metadata is not taken for a protocol-level refusal: the validator decides", async () => {
    const t = new MockTransport();
    const onFlowError = vi.fn();
    const onRefusedCompletion = vi.fn();
    new Peer(t, {
      handler: { onFlowError },
      onRefusedCompletion,
      validator: { validateMethod: () => [{ path: "wmp", message: "required" }] },
    });
    t.receive({ jsonrpc: "2.0", method: "wmp.flow.complete", params: { flow_id: "f1", result: null } } as never);
    t.receive(complete("f2", { credential_response_encrypted: true, credentials: [{ credential: "x" }] }, null));
    t.receive(complete("f3", { credential_response_encrypted: true, credentials: [{ credential: "x" }] }, {}));
    await settle();
    expect(onRefusedCompletion).not.toHaveBeenCalled();
    expect(onFlowError).not.toHaveBeenCalled();
  });
});

describe("Peer: finished flows release their context", () => {
  const settle = () => new Promise((r) => setTimeout(r, 10));
  const startReq = (i: number) => ({
    jsonrpc: "2.0" as const,
    id: `s${i}`,
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: `f${i}`, params: {} },
  });

  async function responder() {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    return { t, peer };
  }

  it("flowComplete / flowError of an accepted incoming flow free its slot (4100 sequential flows)", async () => {
    const { t, peer } = await responder();
    for (let i = 0; i < 4100; i++) {
      t.receive(startReq(i));
      await Promise.resolve();
      await Promise.resolve();
      if (i % 2) await peer.flowComplete(`f${i}`, {});
      else await peer.flowError(`f${i}`, -31006, "x");
    }
    await settle();
    const errors = t.sent.filter((m) => (m as Response).error);
    expect(errors).toHaveLength(0); // never -31007
  });

  it("a profile's notify of the terminal message frees the slot too", async () => {
    const { t, peer } = await responder();
    for (let i = 0; i < 4100; i++) {
      t.receive(startReq(i));
      await Promise.resolve();
      await Promise.resolve();
      await peer.notify("wmp.flow.complete", { wmp: { version: "0.1" }, flow_id: `f${i}`, result: {} });
    }
    await settle();
    expect(t.sent.filter((m) => (m as Response).error)).toHaveLength(0);
  });

  it("an outgoing flowCancel that succeeds frees the id (and a failed one does not)", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    const c1 = peer.flowCancel("f1");
    await settle();
    // the cancel fails: the flow is still active
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, error: { code: -31006, message: "no" } });
    await expect(c1).rejects.toBeDefined();
    await expect(peer.startFlow("sign", "f1", {})).rejects.toMatchObject({ code: -32602 });
    const c2 = peer.flowCancel("f1");
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[2] as { id: string }).id, result: { wmp: { version: "0.1" }, flow_id: "f1", status: "cancelled" } });
    await c2;
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(2);
  });
});

describe("Peer: finished flows, malformed envelopes and sessions (round 4)", () => {
  const settle = () => new Promise((r) => setTimeout(r, 10));
  const query = { credentials: [{ id: "pid" }] };
  const secret = { satisfiable: true, claims: { name: "secret" } };
  const complete = (flowId: string, result?: unknown, wmp: unknown = { version: "0.1" }) => ({
    jsonrpc: "2.0" as const,
    method: "wmp.flow.complete",
    params: { ...(wmp === null ? {} : { wmp }), flow_id: flowId, ...(result === undefined ? {} : { result }) },
  });
  const startMatch = (id: string, flowId: string) => ({
    jsonrpc: "2.0" as const,
    id,
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1" }, flow_type: "match", flow_id: flowId, params: { dcql_query: query } },
  });
  const matchPeer = () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowComplete, onFlowError } });
    return { t, peer, onFlowComplete, onFlowError };
  };

  it("a completion without wmp metadata is not delivered when there is no schema validator", async () => {
    const { t, onFlowComplete, onFlowError } = matchPeer();
    t.receive(startMatch("s", "m1"));
    await settle();
    t.receive(complete("m1", secret, null));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).not.toHaveBeenCalled(); // malformed: dropped, not a flow outcome
    t.receive(complete("m1", { satisfiable: true })); // a well-formed one still works
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("the same invalid match completion sent twice is refused once and ignored after", async () => {
    const { t, onFlowComplete, onFlowError } = matchPeer();
    t.receive(startMatch("s", "m1"));
    await settle();
    t.receive(complete("m1", secret));
    t.receive(complete("m1", secret));
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("after a match flow ended normally, a claim-bearing repeat is ignored, not judged by the general rules", async () => {
    const { t, onFlowComplete } = matchPeer();
    t.receive(startMatch("s", "m1"));
    await settle();
    t.receive(complete("m1", { satisfiable: true }));
    await settle();
    t.receive(complete("m1", secret));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("an ended flow holds no active slot, and a restarted id is judged afresh", async () => {
    const { t, onFlowComplete, onFlowError } = matchPeer();
    t.receive(startMatch("s1", "m1"));
    await settle();
    t.receive(complete("m1", { satisfiable: true }));
    await settle();
    t.receive(startMatch("s2", "m1")); // the id is free again
    await settle();
    expect((t.sent[1] as Response).error).toBeUndefined();
    t.receive(complete("m1", secret));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  async function clientSession(sid: string, t: MockTransport, peer: Peer) {
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: "rt" } });
    await p;
  }

  it("closing or replacing a session clears the old session's flow contexts and markers", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    await clientSession("ses-1", t, peer);
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    await expect(peer.startFlow("sign", "f1", {})).rejects.toMatchObject({ code: -32602 }); // active in ses-1
    await peer.closeSession();
    await clientSession("ses-2", t, peer);
    peer.startFlow("sign", "f1", {}).catch(() => {}); // the id is usable in the new session
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(2);

    // replacement without a close
    await clientSession("ses-3", t, peer);
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(3);
  });

  it("an incoming session.close or a new incoming session clears them too", async () => {
    const { t, onFlowComplete } = (() => {
      const t = new MockTransport();
      const onFlowComplete = vi.fn();
      new Peer(t, {
        handler: {
          onSessionCreate: async () => ({ wmp: { version: "0.1", session_id: "ses-N" }, capabilities: {}, security: { mode: "tls" } }),
          onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }),
          onFlowComplete,
        },
      });
      return { t, onFlowComplete };
    })();
    const start = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f1", params: {} } });
    t.receive(start("a"));
    await settle();
    t.receive(start("b")); // duplicate while active
    await settle();
    expect((t.sent[1] as Response).error?.code).toBe(-32602);
    t.receive({ jsonrpc: "2.0", id: "c", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    t.receive(start("d")); // allowed in the new session
    await settle();
    expect((t.sent.at(-1) as Response).error).toBeUndefined();
    t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1" }, reason: "complete" } });
    await settle();
    t.receive(complete("f1", { credentials: [] })); // old marker/context are gone: a plain completion is delivered
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("closeSession alone frees the closed session's flow ids", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    await clientSession("ses-1", t, peer);
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    await peer.closeSession();
    peer.startFlow("sign", "f1", {}).catch(() => {}); // no new session yet: the id is free
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(2);
  });

  it("an incoming session.close alone frees the closed session's flow ids", async () => {
    const t = new MockTransport();
    new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    const start = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f1", params: {} } });
    t.receive(start("a"));
    await settle();
    t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1" }, reason: "complete" } });
    await settle();
    t.receive(start("b"));
    await settle();
    expect((t.sent[1] as Response).error).toBeUndefined();
  });

  it("resuming the same session keeps its flow state", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    await clientSession("ses-1", t, peer);
    peer.startFlow("sign", "f1", {}).catch(() => {});
    await settle();
    const resume = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await resume;
    await expect(peer.startFlow("sign", "f1", {})).rejects.toMatchObject({ code: -32602 }); // still active
    const other = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-2" }, resumed: true, missed_messages: 0, security: { mode: "tls" } } });
    await other;
    peer.startFlow("sign", "f1", {}).catch(() => {}); // a different session: cleared
    await settle();
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.flow.start")).toHaveLength(2);
  });
});
