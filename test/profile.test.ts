import { describe, it, expect } from "vitest";
import {
  Registry,
  type Profile,
  type PeerContext,
  type FlowHandler,
  type MethodHandler,
  type ResolveHandler,
} from "../src/profile.js";
import type {
  FlowStartParams,
  FlowStartResult,
  FlowActionParams,
  FlowActionResult,
  FlowProgressParams,
  FlowCompleteParams,
  FlowErrorParams,
  ResolveParams,
  ResolveResult,
} from "../src/types.js";

// A profile that implements all sub-interfaces.
class TestProfile
  implements Profile, FlowHandler, MethodHandler, ResolveHandler
{
  name = "test";
  capabilities() {
    return ["test_cap"];
  }
  init(_ctx: PeerContext) {}

  flowTypes() {
    return ["test_flow"];
  }
  async startFlow(params: FlowStartParams): Promise<FlowStartResult> {
    return {
      wmp: params.wmp,
      flow_id: params.flow_id,
      flow_type: params.flow_type,
    };
  }
  async handleAction(params: FlowActionParams): Promise<FlowActionResult> {
    return {
      wmp: params.wmp,
      flow_id: params.flow_id,
      action: params.action,
      status: "ok",
    };
  }
  handleProgress(_p: FlowProgressParams) {}
  handleComplete(_p: FlowCompleteParams) {}
  handleError(_p: FlowErrorParams) {}

  methods() {
    return ["test.echo"];
  }
  async handleMethod(_method: string, params: unknown) {
    return params;
  }

  resolveTypes() {
    return ["test_resolve"];
  }
  async handleResolve(params: ResolveParams): Promise<ResolveResult> {
    return {
      wmp: params.wmp,
      type: params.type,
      uri: params.uri,
      metadata: { resolved: true },
    };
  }
}

describe("Registry", () => {
  it("registers a profile and looks up handlers", () => {
    const reg = new Registry();
    reg.register(new TestProfile());

    expect(reg.getFlowHandler("test_flow")).toBeDefined();
    expect(reg.getMethodHandler("test.echo")).toBeDefined();
    expect(reg.getResolveHandler("test_resolve")).toBeDefined();
    expect(reg.allCapabilities()).toEqual(["test_cap"]);
  });

  it("returns undefined for unknown handlers", () => {
    const reg = new Registry();
    expect(reg.getFlowHandler("nope")).toBeUndefined();
    expect(reg.getMethodHandler("nope")).toBeUndefined();
    expect(reg.getResolveHandler("nope")).toBeUndefined();
  });

  it("throws on duplicate flow type", () => {
    const reg = new Registry();
    reg.register(new TestProfile());
    expect(() => reg.register(new TestProfile())).toThrow(
      'Flow type "test_flow" already registered',
    );
  });

  it("registers a profile with no sub-interfaces", () => {
    const reg = new Registry();
    const simple: Profile = {
      name: "simple",
      capabilities: () => ["basic"],
      init: () => {},
    };
    reg.register(simple);
    expect(reg.allCapabilities()).toEqual(["basic"]);
  });
});
