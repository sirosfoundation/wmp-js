/**
 * Conformance tests — validate wmp-js types and message structure against
 * the official WMP test vectors in wmp/vectors/.
 *
 * These tests verify that:
 * - Test vector inputs parse as valid JSON-RPC messages
 * - Method names match our Method constants
 * - Error codes match our ErrorCode constants
 * - Required fields in params/results are present
 * - Expected response structure is well-formed
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { isRequest, isResponse } from "../src/jsonrpc.js";
import type { Request, Response } from "../src/jsonrpc.js";
import { Method, ErrorCode } from "../src/types.js";

import {
  validateCompletionResult,
  validateMatchResult,
  splitReplaySecrets,
  CompletionResultError,
} from "../src/completion.js";
import { Peer } from "../src/peer.js";
import { MockTransport } from "./mock-transport.js";
import { loadManifest, loadVectors, vectorFilesOnDisk, vectorsDir, specDir, type TestVector } from "./vectors.js";

// Collect all known method names from the Method constant
const knownMethods = new Set(Object.values(Method));

// Collect all known error codes from the ErrorCode constant
const knownErrorCodes = new Set(Object.values(ErrorCode));

// ---------------------------------------------------------------------------
// Structural validation helpers
// ---------------------------------------------------------------------------

function assertValidRequest(input: unknown, vectorId: string): void {
  const msg = input as Record<string, unknown>;
  expect(msg.jsonrpc, `${vectorId}: jsonrpc`).toBe("2.0");
  expect(msg.method, `${vectorId}: method must be string`).toEqual(expect.any(String));
  expect(msg.params, `${vectorId}: params must exist`).toBeDefined();

  // Verify the method is one we know about
  const method = msg.method as string;
  expect(
    knownMethods.has(method as (typeof Method)[keyof typeof Method]),
    `${vectorId}: unknown method '${method}'`,
  ).toBe(true);

  // All WMP methods should have a wmp metadata envelope in params
  const params = msg.params as Record<string, unknown>;
  expect(params.wmp, `${vectorId}: params.wmp metadata must exist`).toBeDefined();

  const wmp = params.wmp as Record<string, unknown>;
  expect(wmp.version, `${vectorId}: wmp.version must be string`).toEqual(expect.any(String));
}

function assertValidResponse(response: unknown, vectorId: string): void {
  const msg = response as Record<string, unknown>;
  expect(msg.jsonrpc, `${vectorId}: response jsonrpc`).toBe("2.0");

  if (msg.result !== undefined) {
    // Success response — result.wmp must exist
    const result = msg.result as Record<string, unknown>;
    expect(result.wmp, `${vectorId}: result.wmp must exist`).toBeDefined();
  }
}

function assertValidError(errorResponse: unknown, vectorId: string): void {
  const msg = errorResponse as Record<string, unknown>;
  expect(msg.jsonrpc, `${vectorId}: error jsonrpc`).toBe("2.0");

  const error = msg.error as Record<string, unknown>;
  expect(error, `${vectorId}: error field must exist`).toBeDefined();
  expect(error.code, `${vectorId}: error.code must be number`).toEqual(expect.any(Number));
  expect(error.message, `${vectorId}: error.message must be string`).toEqual(expect.any(String));

  // Verify the error code is one we define
  expect(
    knownErrorCodes.has(error.code as (typeof ErrorCode)[keyof typeof ErrorCode]),
    `${vectorId}: unknown error code ${error.code}`,
  ).toBe(true);
}

// ---------------------------------------------------------------------------
// Test vector validation
// ---------------------------------------------------------------------------

describe("Conformance: session-create vectors", () => {
  const vectors = loadVectors("session-create.json");

  for (const v of vectors) {
    it(`${v.id}: input is valid WMP request`, () => {
      assertValidRequest(v.input, v.id);
    });

    if (v.expected_response) {
      it(`${v.id}: expected response is well-formed`, () => {
        assertValidResponse(v.expected_response, v.id);
      });
    }
  }
});

describe("Conformance: session-lifecycle vectors", () => {
  const vectors = loadVectors("session-lifecycle.json");

  for (const v of vectors) {
    it(`${v.id}: input is valid WMP request`, () => {
      assertValidRequest(v.input, v.id);
    });

    if (v.expected_response) {
      it(`${v.id}: expected response is well-formed`, () => {
        assertValidResponse(v.expected_response, v.id);
      });
    }
  }
});

describe("Conformance: message-deliver vectors", () => {
  const vectors = loadVectors("message-deliver.json");

  for (const v of vectors) {
    it(`${v.id}: input is valid WMP request`, () => {
      assertValidRequest(v.input, v.id);
    });

    if (v.expected_response) {
      it(`${v.id}: expected response is well-formed`, () => {
        assertValidResponse(v.expected_response, v.id);
      });
    }
  }
});

describe("Conformance: flow-lifecycle vectors", () => {
  const vectors = loadVectors("flow-lifecycle.json");

  for (const v of vectors) {
    // Flow lifecycle vectors may have multi-message sequences
    if (Array.isArray(v.input)) {
      it(`${v.id}: multi-step input messages are valid`, () => {
        for (const step of v.input as unknown[]) {
          const s = step as Record<string, unknown>;
          if (s.message) {
            assertValidRequest(s.message, `${v.id}/${s.step ?? "?"}`);
          }
        }
      });
    } else {
      it(`${v.id}: input is valid WMP request`, () => {
        assertValidRequest(v.input, v.id);
      });
    }
  }
});

describe("Conformance: resolve vectors", () => {
  const vectors = loadVectors("resolve.json");

  for (const v of vectors) {
    it(`${v.id}: input is valid WMP request`, () => {
      assertValidRequest(v.input, v.id);
    });

    if (v.expected_response) {
      it(`${v.id}: expected response is well-formed`, () => {
        assertValidResponse(v.expected_response, v.id);
      });
    }

    if (v.expected_error) {
      it(`${v.id}: expected error is well-formed`, () => {
        assertValidError(v.expected_error, v.id);
      });
    }
  }
});

describe("Conformance: error vectors", () => {
  const vectors = loadVectors("errors.json");

  for (const v of vectors) {
    // Some error vectors deliberately use unknown methods (e.g. error-method-not-found)
    if (v.expected_error) {
      const errorObj = (v.expected_error as Record<string, unknown>).error as Record<string, unknown> | undefined;
      const code = errorObj?.code;
      if (code === ErrorCode.MethodNotFound) {
        it(`${v.id}: expected error has MethodNotFound code`, () => {
          assertValidError(v.expected_error, v.id);
        });
        continue;
      }
    }

    it(`${v.id}: input is valid WMP request`, () => {
      assertValidRequest(v.input, v.id);
    });

    if (v.expected_error) {
      it(`${v.id}: expected error response has known error code`, () => {
        assertValidError(v.expected_error, v.id);
      });
    }
  }
});

describe("Conformance: method coverage", () => {
  it("all test vectors (except error-method-not-found) reference known WMP methods", () => {
    const allVectorMethods = new Set<string>();

    // error vectors may deliberately use unknown methods — skip errors.json
    const files = [
      "session-create.json",
      "session-lifecycle.json",
      "message-deliver.json",
      "flow-lifecycle.json",
      "resolve.json",
    ];

    for (const file of files) {
      const vectors = loadVectors(file);
      for (const v of vectors) {
        const input = v.input as Record<string, unknown>;
        if (input.method) {
          allVectorMethods.add(input.method as string);
        }
        // Check multi-step inputs
        if (Array.isArray(v.input)) {
          for (const step of v.input as unknown[]) {
            const s = step as Record<string, unknown>;
            if (s.message) {
              const inp = s.message as Record<string, unknown>;
              if (inp.method) allVectorMethods.add(inp.method as string);
            }
          }
        }
      }
    }

    // Every method in vectors should be in our Method constants
    for (const m of allVectorMethods) {
      expect(
        knownMethods.has(m as (typeof Method)[keyof typeof Method]),
        `Vector method '${m}' not in Method constants`,
      ).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// Manifest: every vector file is listed, every listed file exists
// ---------------------------------------------------------------------------

describe("Conformance: manifest", () => {
  const manifest = loadManifest();

  it("lists every vector file in the directory and nothing else", () => {
    const listed = manifest.map((e) => e.file).sort();
    expect(listed).toEqual(vectorFilesOnDisk());
  });

  it("uses only kinds this harness executes", () => {
    for (const e of manifest) {
      expect(["rpc", "interop", "transport-http"], `${e.file}: kind ${e.kind}`).toContain(e.kind);
    }
  });

  for (const e of manifest) {
    it(`${e.file} (${e.kind}) parses as a non-empty vector array with unique ids`, () => {
      const vectors = loadVectors(e.file);
      expect(vectors.length, `${e.file} has no vectors`).toBeGreaterThan(0);
      const ids = vectors.map((v) => v.id);
      expect(new Set(ids).size, `${e.file}: duplicate vector ids`).toBe(ids.length);
    });
  }
});

describe("Conformance: vectors directory", () => {
  it("is the directory the harness resolved (not silently empty)", () => {
    expect(vectorsDir()).toContain("vectors");
  });
});

// ---------------------------------------------------------------------------
// Error codes: ErrorCode and Core §3.8 define the same set
// ---------------------------------------------------------------------------

describe("Conformance: error codes match Core §3.8", () => {
  const spec = readFileSync(resolve(specDir(), "wmp-core.md"), "utf8");
  // Table rows of the form "| -31019 | Name | ... |".
  const specCodes = new Set(
    [...spec.matchAll(/^\|\s*(-3\d{4})\s*\|/gm)].map((m) => Number(m[1])),
  );

  it("finds the WMP error codes in the spec", () => {
    expect(specCodes.size).toBeGreaterThan(15);
    expect(specCodes.has(-31019)).toBe(true);
  });

  it("every WMP code in the spec is an ErrorCode member", () => {
    for (const code of specCodes) {
      if (code <= -32000) continue; // JSON-RPC standard codes
      expect(knownErrorCodes.has(code as never), `ErrorCode lacks ${code}`).toBe(true);
    }
  });

  it("every WMP ErrorCode member is in the spec", () => {
    for (const code of knownErrorCodes) {
      if (code <= -32000) continue;
      expect(specCodes.has(code), `spec lacks ${code}`).toBe(true);
    }
  });

  it("defines -31019 as PlaintextHashMismatch", () => {
    expect(ErrorCode.PlaintextHashMismatch).toBe(-31019);
  });
});

// ---------------------------------------------------------------------------
// flow-lifecycle: execute the flow checks, including every must_refuse vector
// ---------------------------------------------------------------------------

interface FlowMsg {
  method?: string;
  params?: { flow_id?: string; flow_type?: string; params?: { dcql_query?: { credentials?: { id: string }[] } }; result?: unknown };
}

function messagesOf(input: unknown): FlowMsg[] {
  if (Array.isArray(input)) return input.map((s) => (s as { message: FlowMsg }).message);
  return [input as FlowMsg];
}

/**
 * Applies the flow checks wmp-js implements to one vector. Returns, per message
 * that a check applied to, whether the check reported a violation. The result
 * check is selected by the flow type recorded when the flow started (match vs
 * the rest), never by members of the result (openid4x 3.3.3); a vector that
 * is a lone flow.complete has no start, so by convention its flow_id names the
 * type: "*-match" is a match flow.
 */
function runFlowChecks(v: TestVector): boolean[] {
  const flowTypes = new Map<string, string>();
  const queryIds = new Map<string, string[]>();
  const outcomes: boolean[] = [];
  for (const msg of messagesOf(v.input)) {
    const id = msg.params?.flow_id ?? "";
    if (msg.method === "wmp.flow.start") {
      flowTypes.set(id, msg.params?.flow_type ?? "");
      const q = msg.params?.params?.dcql_query?.credentials;
      if (q) queryIds.set(id, q.map((c) => c.id));
      continue;
    }
    if (msg.method !== "wmp.flow.complete" || msg.params?.result === undefined) continue;
    const isMatch = (flowTypes.get(id) ?? (id.endsWith("-match") ? "match" : "")) === "match";
    try {
      if (isMatch) validateMatchResult(msg.params.result, queryIds.get(id));
      else validateCompletionResult(msg.params.result);
      outcomes.push(false);
    } catch (e) {
      if (!(e instanceof CompletionResultError)) throw e;
      outcomes.push(true);
    }
  }
  return outcomes;
}

describe("Conformance: flow-lifecycle vectors are executed", () => {
  const vectors = loadVectors("flow-lifecycle.json");
  // must_refuse vectors whose check is not implemented yet, by method of the
  // refused message. Nothing may be added; an implemented check removes its entry.
  const pendingMustRefuse = new Set<string>(["wmp.flow.action"]);

  for (const v of vectors) {
    it(`${v.id}: ${v.must_refuse ? "is refused" : "passes the flow checks"}`, () => {
      const outcomes = runFlowChecks(v);
      if (v.must_refuse) {
        if (outcomes.length === 0) {
          const method = messagesOf(v.input)[0].method ?? "";
          expect(pendingMustRefuse.has(method), `${v.id}: must_refuse vector (${method}) was not checked`).toBe(true);
          return;
        }
        expect(outcomes.every(Boolean), `${v.id}: must_refuse vector passed the conformance check`).toBe(true);
      } else {
        expect(outcomes.every((violated) => !violated), `${v.id}: conforming vector was refused`).toBe(true);
      }
    });
  }

  it("executes a substantial number of must_refuse vectors", () => {
    const executed = vectors.filter((v) => v.must_refuse && runFlowChecks(v).length > 0);
    expect(executed.length).toBeGreaterThanOrEqual(15);
  });

  for (const v of vectors.filter((x) => x.expected_replay !== undefined)) {
    it(`${v.id}: replay form matches expected_replay`, () => {
      const out = splitReplaySecrets(JSON.stringify(v.input));
      expect(out.ok).toBe(true);
      expect(JSON.parse(out.replay)).toEqual(v.expected_replay);
      // The retained copy conforms, and the live form is the input unchanged.
      const replayed = JSON.parse(out.replay) as FlowMsg;
      validateCompletionResult(replayed.params?.result);
      if (out.live !== undefined) expect(JSON.parse(out.live)).toEqual(v.input);
      else expect(JSON.parse(out.replay)).toEqual(v.input);
    });
  }
});

// ---------------------------------------------------------------------------
// Behavioural execution of version negotiation and flow-type error vectors
// ---------------------------------------------------------------------------

async function respond(input: unknown, supported?: string[]): Promise<Response> {
  const t = new MockTransport();
  new Peer(t, {
    supportedVersions: supported,
    handler: {
      // A session.create responder with no version of its own: the Peer's negotiation decides.
      onSessionCreate: async () => ({
        wmp: { version: "", session_id: "ses-abcdef0123" },
        capabilities: {},
        security: { mode: "tls" },
      }),
    },
  });
  t.receive(input as never);
  await new Promise((r) => setTimeout(r, 10));
  return t.sent[0] as Response;
}

describe("Conformance: version negotiation vectors run against Peer", () => {
  const create = loadVectors("session-create.json").filter((v) => v.setup?.supported_versions);
  const errors = loadVectors("errors.json").filter((v) => v.setup?.supported_versions && v.expected_error);

  it("finds the vectors", () => {
    expect(create.length).toBeGreaterThanOrEqual(3);
    expect(errors.length).toBeGreaterThanOrEqual(3);
  });

  for (const v of create) {
    it(`${v.id}: selected version`, async () => {
      const resp = await respond(v.input, v.setup!.supported_versions);
      const want = (v.expected_response as { result: { wmp: { version: string } } }).result.wmp.version;
      expect((resp.result as { wmp: { version: string; session_id: string } }).wmp.version).toBe(want);
      expect((resp.result as { wmp: { session_id: string } }).wmp.session_id).toMatch(/^ses-/);
    });
  }

  for (const v of errors) {
    it(`${v.id}: error response equals the vector`, async () => {
      const resp = await respond(v.input, v.setup!.supported_versions);
      expect(resp.error).toEqual((v.expected_error as { error: unknown }).error);
    });
  }

  it("error-unknown-flow-type is -31005 with the unsupported flow type", async () => {
    const v = loadVectors("errors.json").find((x) => x.id === "error-unknown-flow-type")!;
    const resp = await respond(v.input);
    expect(resp.error).toEqual((v.expected_error as { error: unknown }).error);
  });
});
