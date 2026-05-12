import { describe, it, expect } from "vitest";
import {
  OID4FlowType,
  VCIStep,
  VPStep,
  OID4Action,
  OpenID4xProfile,
} from "../src/openid4x.js";
import type { FlowStartParams, FlowActionParams, Metadata } from "../src/types.js";
import { ErrorCode } from "../src/types.js";

const wmp: Metadata = { version: "0.1", session_id: "ses-1" };

describe("OpenID4x constants", () => {
  it("defines flow types", () => {
    expect(OID4FlowType.OID4VCI).toBe("oid4vci");
    expect(OID4FlowType.OID4VP).toBe("oid4vp");
  });

  it("defines VCI steps", () => {
    expect(VCIStep.ParsingOffer).toBe("parsing_offer");
    expect(VCIStep.CredentialReceived).toBe("credential_received");
    expect(Object.keys(VCIStep)).toHaveLength(11);
  });

  it("defines VP steps", () => {
    expect(VPStep.ParsingRequest).toBe("parsing_request");
    expect(VPStep.GeneratingPresentation).toBe("generating_presentation");
    expect(Object.keys(VPStep)).toHaveLength(7);
  });

  it("defines actions", () => {
    expect(OID4Action.AcceptOffer).toBe("accept_offer");
    expect(OID4Action.Cancel).toBe("cancel");
    expect(Object.keys(OID4Action)).toHaveLength(5);
  });
});

describe("OpenID4xProfile capabilities", () => {
  it("reports oid4vci when configured", () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: ["pre-authorized"], supported_formats: ["jwt_vc_json"] },
    });
    expect(p.capabilities()).toEqual(["oid4vci"]);
    expect(p.flowTypes()).toEqual(["oid4vci"]);
  });

  it("reports both when configured", () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
      oid4vp: { supported_response_modes: ["direct_post"], supported_formats: ["jwt_vp_json"] },
    });
    expect(p.capabilities()).toEqual(["oid4vci", "oid4vp"]);
    expect(p.flowTypes()).toEqual(["oid4vci", "oid4vp"]);
  });

  it("reports empty when nothing configured", () => {
    const p = new OpenID4xProfile({});
    expect(p.capabilities()).toEqual([]);
    expect(p.flowTypes()).toEqual([]);
  });

  it("has name 'openid4x'", () => {
    const p = new OpenID4xProfile({});
    expect(p.name).toBe("openid4x");
  });

  it("exposes vctm and issuer_metadata resolve types", () => {
    const p = new OpenID4xProfile({});
    expect(p.resolveTypes()).toEqual(["vctm", "issuer_metadata"]);
  });
});

describe("OpenID4xProfile flow dispatch", () => {
  it("starts OID4VCI flow with default handler", async () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
    });

    const params: FlowStartParams = {
      wmp,
      flow_type: "oid4vci",
      flow_id: "flow-1",
    };

    const result = await p.startFlow(params);
    expect(result.flow_id).toBe("flow-1");
    expect(result.flow_type).toBe("oid4vci");
  });

  it("starts OID4VP flow with custom handler", async () => {
    const p = new OpenID4xProfile({
      oid4vp: { supported_response_modes: [], supported_formats: [] },
      onVPStart: async (params) => ({
        wmp: params.wmp,
        flow_id: params.flow_id,
        flow_type: params.flow_type,
      }),
    });

    const result = await p.startFlow({
      wmp,
      flow_type: "oid4vp",
      flow_id: "flow-2",
    });
    expect(result.flow_id).toBe("flow-2");
  });

  it("calls custom VCI start handler", async () => {
    let called = false;
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
      onVCIStart: async (params) => {
        called = true;
        return { wmp: params.wmp, flow_id: params.flow_id, flow_type: params.flow_type };
      },
    });

    await p.startFlow({ wmp, flow_type: "oid4vci", flow_id: "flow-3" });
    expect(called).toBe(true);
  });

  it("rejects unknown flow type", async () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
    });

    await expect(
      p.startFlow({ wmp, flow_type: "unknown", flow_id: "flow-x" }),
    ).rejects.toMatchObject({ code: ErrorCode.FlowError });
  });
});

describe("OpenID4xProfile action dispatch", () => {
  it("dispatches VCI action to custom handler", async () => {
    let receivedAction = "";
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
      onVCIAction: async (params) => {
        receivedAction = params.action;
        return { wmp: params.wmp, flow_id: params.flow_id, action: params.action, status: "ok" };
      },
    });

    // Start flow first to register flow type
    await p.startFlow({ wmp, flow_type: "oid4vci", flow_id: "flow-a" });

    const result = await p.handleAction({
      wmp,
      flow_id: "flow-a",
      action: OID4Action.AcceptOffer,
    });

    expect(receivedAction).toBe("accept_offer");
    expect(result.status).toBe("ok");
  });

  it("returns default result when no action handler", async () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
    });

    await p.startFlow({ wmp, flow_type: "oid4vci", flow_id: "flow-b" });

    const result = await p.handleAction({
      wmp,
      flow_id: "flow-b",
      action: OID4Action.Cancel,
    });

    expect(result.status).toBe("accepted");
  });

  it("cleans up flow type on complete", async () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
    });

    await p.startFlow({ wmp, flow_type: "oid4vci", flow_id: "flow-c" });
    p.handleComplete({ wmp, flow_id: "flow-c" });

    // After complete, action should get default (no flow type match)
    const result = await p.handleAction({
      wmp,
      flow_id: "flow-c",
      action: "any",
    });
    expect(result.status).toBe("accepted");
  });

  it("cleans up flow type on error", async () => {
    const p = new OpenID4xProfile({
      oid4vci: { supported_grants: [], supported_formats: [] },
    });

    await p.startFlow({ wmp, flow_type: "oid4vci", flow_id: "flow-d" });
    p.handleError({ wmp, flow_id: "flow-d", code: -1, message: "test" });

    const result = await p.handleAction({
      wmp,
      flow_id: "flow-d",
      action: "any",
    });
    expect(result.status).toBe("accepted");
  });
});

describe("OpenID4xProfile resolve", () => {
  it("rejects resolve by default", async () => {
    const p = new OpenID4xProfile({});
    await expect(
      p.handleResolve({ wmp, type: "vctm", uri: "https://example.com" }),
    ).rejects.toMatchObject({ code: ErrorCode.CapabilityNotSupported });
  });
});
