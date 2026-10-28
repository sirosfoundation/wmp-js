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
