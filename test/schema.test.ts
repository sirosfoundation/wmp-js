import { describe, it, expect } from "vitest";
import { join } from "node:path";
import { createValidator } from "../src/schema.js";

// Path to the WMP schema files (in the spec repo).
const SCHEMA_DIR = join(__dirname, "..", "..", "wmp", "schema");

describe("schema validation", () => {
  const validator = createValidator(SCHEMA_DIR);

  it("lists method schemas", () => {
    const methods = validator.methodSchemas();
    expect(methods.length).toBeGreaterThan(0);
    expect(methods).toContain("wmp.session.create");
    expect(methods).toContain("wmp.flow.start");
    expect(methods).toContain("wmp.resolve");
  });

  it("validates valid session.create request", () => {
    const msg = {
      jsonrpc: "2.0",
      id: 1,
      method: "wmp.session.create",
      params: {
        wmp: { version: "0.1" },
      },
    };
    const errors = validator.validateMethod("wmp.session.create", msg);
    expect(errors).toBeNull();
  });

  it("rejects session.create missing params", () => {
    const msg = {
      jsonrpc: "2.0",
      id: 1,
      method: "wmp.session.create",
    };
    const errors = validator.validateMethod("wmp.session.create", msg);
    expect(errors).not.toBeNull();
  });

  it("validates valid flow.start request", () => {
    const msg = {
      jsonrpc: "2.0",
      id: "flow-1",
      method: "wmp.flow.start",
      params: {
        wmp: { version: "0.1" },
        flow_type: "oid4vci",
        flow_id: "f-001",
      },
    };
    const errors = validator.validateMethod("wmp.flow.start", msg);
    expect(errors).toBeNull();
  });

  it("rejects flow.start missing flow_type", () => {
    const msg = {
      jsonrpc: "2.0",
      id: "flow-1",
      method: "wmp.flow.start",
      params: {
        wmp: { version: "0.1" },
        flow_id: "f-001",
      },
    };
    const errors = validator.validateMethod("wmp.flow.start", msg);
    expect(errors).not.toBeNull();
  });

  it("validates valid flow.progress notification", () => {
    const msg = {
      jsonrpc: "2.0",
      method: "wmp.flow.progress",
      params: {
        wmp: { version: "0.1" },
        flow_id: "f-001",
        step: "metadata_fetched",
        payload: { issuer_metadata: {} },
      },
    };
    const errors = validator.validateMethod("wmp.flow.progress", msg);
    expect(errors).toBeNull();
  });

  it("validates valid resolve request", () => {
    const msg = {
      jsonrpc: "2.0",
      id: "r-1",
      method: "wmp.resolve",
      params: {
        wmp: { version: "0.1" },
        type: "vctm",
        uri: "https://example.com/vctm/pid",
      },
    };
    const errors = validator.validateMethod("wmp.resolve", msg);
    expect(errors).toBeNull();
  });

  it("returns null for unknown methods", () => {
    const msg = { jsonrpc: "2.0", method: "unknown", id: 1 };
    expect(validator.validateMethod("unknown", msg)).toBeNull();
  });

  it("validates session.create response", () => {
    const msg = {
      jsonrpc: "2.0",
      id: 1,
      result: {
        wmp: { version: "0.1" },
        capabilities: {},
      },
    };
    const errors = validator.validateResponse("wmp.session.create", msg);
    expect(errors).toBeNull();
  });
});
