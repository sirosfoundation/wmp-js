import { describe, it, expect } from "vitest";
import {
  OID4FlowType,
  VCIStep,
  VPStep,
  OID4Action,
  OpenID4xProfile,
  buildVCIFlowStart,
  withAttestation,
} from "../src/openid4x.js";
import type {
  ClientAttestationProvider,
  OID4VCIFlowParams,
  CredentialNotificationParams,
} from "../src/openid4x.js";
import type { FlowStartParams, FlowActionParams, Metadata } from "../src/types.js";
import { ErrorCode, VERSION } from "../src/types.js";

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

describe("buildVCIFlowStart", () => {
  it("builds flow start params with offer", () => {
    const params: OID4VCIFlowParams = { offer: "openid-credential-offer://example" };
    const result = buildVCIFlowStart("ses-1", "flow-1", params);

    expect(result.wmp.version).toBe(VERSION);
    expect(result.wmp.session_id).toBe("ses-1");
    expect(result.flow_type).toBe("oid4vci");
    expect(result.flow_id).toBe("flow-1");
    expect(result.params).toBe(params);
    expect(result.timeout).toBeUndefined();
  });

  it("builds flow start params with credential_offer_uri", () => {
    const params: OID4VCIFlowParams = { credential_offer_uri: "https://issuer.example/offer/123" };
    const result = buildVCIFlowStart("ses-2", "flow-2", params, 30000);

    expect(result.wmp.version).toBe(VERSION);
    expect(result.flow_type).toBe("oid4vci");
    expect(result.flow_id).toBe("flow-2");
    expect(result.params).toEqual({ credential_offer_uri: "https://issuer.example/offer/123" });
    expect(result.timeout).toBe(30000);
  });

  it("includes attestation fields when present in params", () => {
    const params: OID4VCIFlowParams = {
      offer: "openid-credential-offer://example",
      client_attestation: "wia-jwt",
      client_attestation_pop: "pop-jwt",
    };
    const result = buildVCIFlowStart("ses-3", "flow-3", params);
    expect((result.params as typeof params).client_attestation).toBe("wia-jwt");
    expect((result.params as typeof params).client_attestation_pop).toBe("pop-jwt");
  });
});

describe("withAttestation", () => {
  it("merges attestation into params when provider returns credentials", async () => {
    const provider: ClientAttestationProvider = {
      getAttestation: async (_audience) => ({
        client_attestation: "wia-test-jwt",
        client_attestation_pop: "pop-test-jwt",
      }),
    };
    const params: OID4VCIFlowParams = { offer: "openid-credential-offer://example" };
    const result = await withAttestation(provider, "https://issuer.example", params);

    expect(result.client_attestation).toBe("wia-test-jwt");
    expect(result.client_attestation_pop).toBe("pop-test-jwt");
    expect((result as { offer: string }).offer).toBe("openid-credential-offer://example");
  });

  it("returns params unchanged when provider returns null", async () => {
    const provider: ClientAttestationProvider = {
      getAttestation: async () => null,
    };
    const params: OID4VCIFlowParams = { offer: "openid-credential-offer://example" };
    const result = await withAttestation(provider, "https://issuer.example", params);

    expect(result).toBe(params); // same reference — no modification
  });

  it("passes audience to provider", async () => {
    let receivedAudience = "";
    const provider: ClientAttestationProvider = {
      getAttestation: async (audience) => {
        receivedAudience = audience;
        return null;
      },
    };
    const params: OID4VCIFlowParams = { credential_offer_uri: "https://issuer.example/offer" };
    await withAttestation(provider, "https://as.issuer.example", params);

    expect(receivedAudience).toBe("https://as.issuer.example");
  });
});

describe("CredentialNotificationParams type", () => {
  it("can construct a valid notification payload", () => {
    const notification: CredentialNotificationParams = {
      wmp: { version: VERSION, session_id: "ses-1" },
      flow_id: "flow-1",
      notification_id: "notif-123",
      event: "credential_accepted",
    };
    expect(notification.event).toBe("credential_accepted");
    expect(notification.notification_id).toBe("notif-123");
  });

  it("supports event_description", () => {
    const notification: CredentialNotificationParams = {
      wmp: { version: VERSION, session_id: "ses-1" },
      flow_id: "flow-1",
      notification_id: "notif-456",
      event: "credential_failure",
      event_description: "User revoked consent",
    };
    expect(notification.event).toBe("credential_failure");
    expect(notification.event_description).toBe("User revoked consent");
  });
});
