import { describe, it, expect } from "vitest";
import {
  ActionParamsError,
  buildSelectCredentials,
  isQueryId,
  isSelectionHandle,
  newSelectionHandle,
  validateSelectCredentialsParams,
} from "../src/consent.js";

const H = "Zm9yLXRoZS13YWxsZXQtb25seQ"; // 22 chars
const sel = (extra: Record<string, unknown> = {}) => ({ query_id: "pid", selection_handle: H, ...extra });
const ok = (p: unknown, ctx?: Parameters<typeof validateSelectCredentialsParams>[1]) => expect(() => validateSelectCredentialsParams(p, ctx)).not.toThrow();
const bad = (p: unknown, ctx?: Parameters<typeof validateSelectCredentialsParams>[1], name = JSON.stringify(p)) =>
  expect(() => validateSelectCredentialsParams(p, ctx), name).toThrow(ActionParamsError);

describe("validateSelectCredentialsParams", () => {
  it("accepts consent with selections, and a decline", () => {
    ok({ consent: true, selections: [sel()] });
    ok({ consent: true, selections: [sel(), sel({ query_id: "mdl" })] });
    ok({ consent: false });
    ok({ consent: false, selections: [] });
  });

  it("is a closed set: no credential id, claims, vct, format, free text", () => {
    for (const extra of [{ credential_id: "c" }, { disclosed_claims: ["a"] }, { vct: "x" }, { format: "dc+sd-jwt" }, { claims: { a: "b" } }, { label: "free" }, { x: 1 }]) {
      bad({ consent: true, selections: [sel(extra)] });
    }
    bad({ consent: true, selections: [sel()], credentials: [] });
    bad({ consent: true, selections: [{ credential_id: "c", disclosed_claims: ["a"] }] }); // the old shape
    bad({ consent: false, note: "x" });
  });

  it("applies the shape rules", () => {
    bad({ selections: [sel()] });
    bad({ consent: "true", selections: [sel()] });
    bad({ consent: true });
    bad({ consent: true, selections: [] });
    bad({ consent: true, selections: "x" });
    bad({ consent: false, selections: [sel()] });
    bad({ consent: true, selections: [{ query_id: "pid" }] });
    bad({ consent: true, selections: [{ selection_handle: H }] });
    bad({ consent: true, selections: [null] });
    bad(null);
    bad([]);
    bad("x");
  });

  it("checks the query_id form", () => {
    for (const q of ["my pid!", "a".repeat(257), "", "pid\n", " pid", "a\u0085b", "a b", "a b", "a b", "a　b", "a​b", "a﻿b", "a\u007fb", "a\tb", 5, null]) {
      bad({ consent: true, selections: [sel({ query_id: q })] }, undefined, `query_id ${JSON.stringify(q)}`);
    }
    ok({ consent: true, selections: [sel({ query_id: "id_card.1:å" })] });
    ok({ consent: true, selections: [sel({ query_id: "a".repeat(256) })] });
    ok({ consent: true, selections: [sel({ query_id: "\u{1F600}".repeat(256) })] }); // 256 code points, 512 UTF-16 units
    bad({ consent: true, selections: [sel({ query_id: "\u{1F600}".repeat(257) })] });
  });

  it("checks the selection_handle form", () => {
    for (const h of ["short", H + "==", "A".repeat(25), "A".repeat(22) + "\n", "A".repeat(24) + "\n", "Zm9yLXRoZS13YWxsZXQ+b25seQ", 5, null]) {
      bad({ consent: true, selections: [sel({ selection_handle: h })] }, undefined, `handle ${JSON.stringify(h)}`);
    }
    ok({ consent: true, selections: [sel({ selection_handle: "A".repeat(22) })] });
    ok({ consent: true, selections: [sel({ selection_handle: "A".repeat(24) })] });
  });

  it("requires one handle across elements, distinct query ids", () => {
    bad({ consent: true, selections: [sel(), sel({ query_id: "mdl", selection_handle: "B".repeat(22) })] });
    bad({ consent: true, selections: [sel(), sel()] });
  });

  it("checks the request's query ids and the match handle when given", () => {
    ok({ consent: true, selections: [sel()] }, { queryIds: ["pid", "mdl"], matchHandle: H });
    bad({ consent: true, selections: [sel({ query_id: "other" })] }, { queryIds: ["pid"] });
    bad({ consent: true, selections: [sel()] }, { matchHandle: "B".repeat(22) });
  });

  it("never echoes a value in the error", () => {
    try {
      validateSelectCredentialsParams({ consent: true, selections: [sel({ credential_id: "SECRET-CRED", vct: "SECRET-VCT" })] });
    } catch (e) {
      expect((e as Error).message).not.toContain("SECRET");
    }
  });
});

describe("helpers", () => {
  it("newSelectionHandle is 22 base64url characters and fresh", () => {
    const a = newSelectionHandle();
    const b = newSelectionHandle();
    expect(a).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(isSelectionHandle(a)).toBe(true);
    expect(a).not.toBe(b);
  });

  it("buildSelectCredentials builds the closed shape", () => {
    expect(buildSelectCredentials({ consent: true, queryIds: ["pid", "mdl"], selectionHandle: H })).toEqual({
      consent: true,
      selections: [
        { query_id: "pid", selection_handle: H },
        { query_id: "mdl", selection_handle: H },
      ],
    });
    expect(buildSelectCredentials({ consent: false })).toEqual({ consent: false });
    expect(() => buildSelectCredentials({ consent: true, queryIds: [], selectionHandle: H })).toThrow(ActionParamsError);
    expect(() => buildSelectCredentials({ consent: true, queryIds: ["nope"], selectionHandle: H }, { queryIds: ["pid"] })).toThrow(ActionParamsError);
  });

  it("isQueryId / isSelectionHandle", () => {
    expect(isQueryId("pid")).toBe(true);
    expect(isQueryId("p id")).toBe(false);
    expect(isSelectionHandle(H)).toBe(true);
    expect(isSelectionHandle("x")).toBe(false);
  });
});
