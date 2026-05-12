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

// ---------------------------------------------------------------------------
// Test vector schema
// ---------------------------------------------------------------------------

interface TestVector {
  id: string;
  description: string;
  conformance_level: string;
  input: unknown;
  expected_response?: unknown;
  expected_error?: unknown;
  notes?: string;
}

function loadVectors(filename: string): TestVector[] {
  const path = resolve(__dirname, "../../wmp/vectors", filename);
  const data = readFileSync(path, "utf8");
  return JSON.parse(data) as TestVector[];
}

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
