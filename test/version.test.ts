import { describe, it, expect, vi } from "vitest";
import { negotiateVersion, parseVersion, versionRejection, SUPPORTED_VERSIONS } from "../src/version.js";
import { Peer, type Handler } from "../src/peer.js";
import { OpenID4xProfile } from "../src/openid4x.js";
import { WMPError, type Response } from "../src/jsonrpc.js";
import { ErrorCode } from "../src/types.js";
import { MockTransport } from "./mock-transport.js";

const settle = (ms = 10) => new Promise((r) => setTimeout(r, ms));

describe("parseVersion", () => {
  it("accepts MAJOR.MINOR decimal", () => {
    expect(parseVersion("0.1")).toEqual({ major: 0, minor: 1 });
    expect(parseVersion("1.10")).toEqual({ major: 1, minor: 10 });
    expect(parseVersion("0.0")).toEqual({ major: 0, minor: 0 });
  });
  it("rejects everything else", () => {
    for (const v of ["v0.1", "0.1.0", "0.01", "", "0", ".1", "0.", "-1.0", "0.-1", " 0.1", "0.1 ", "0.1\n", "+0.1", "0.1e1", "1234567.0", undefined, null, 1.1]) {
      expect(parseVersion(v), String(v)).toBeUndefined();
    }
  });
});

describe("negotiateVersion", () => {
  it("selects the highest supported version not above the offer, same MAJOR", () => {
    expect(negotiateVersion("0.2", ["0.1"])).toBe("0.1");
    expect(negotiateVersion("0.2", ["0.1", "0.3"])).toBe("0.1");
    expect(negotiateVersion("0.3", ["0.1", "0.3", "0.2"])).toBe("0.3");
    expect(negotiateVersion("0.10", ["0.9"])).toBe("0.9"); // numeric, not lexical
    expect(negotiateVersion("0.9", ["0.10", "0.9"])).toBe("0.9");
  });
  it("returns undefined for a different major, a too-low offer, or a malformed offer", () => {
    expect(negotiateVersion("1.0", ["0.1"])).toBeUndefined();
    expect(negotiateVersion("0.1", ["0.2"])).toBeUndefined();
    expect(negotiateVersion("v0.1", ["0.1"])).toBeUndefined();
    expect(negotiateVersion("0.1", [])).toBeUndefined();
    expect(negotiateVersion("1.5", ["0.1", "0.2"])).toBeUndefined(); // lower minor, other MAJOR
    expect(negotiateVersion("0.5", ["1.0", "1.2"])).toBeUndefined();
  });
  it("ignores unparseable supported entries and returns the entry unmodified", () => {
    expect(negotiateVersion("0.2", ["bogus", "0.1"])).toBe("0.1");
    expect(negotiateVersion("0.1", ["0.01", "0.0"])).toBe("0.0");
  });
});

describe("versionRejection", () => {
  it("is -32602 for a malformed offer and -31013 with supported_versions otherwise", () => {
    expect(versionRejection("0.1.0", ["0.1"]).code).toBe(ErrorCode.InvalidParams);
    expect(versionRejection(undefined, ["0.1"]).code).toBe(ErrorCode.InvalidParams);
    const e = versionRejection("1.0", ["0.1", "0.2"]);
    expect(e.code).toBe(ErrorCode.VersionNotSupported);
    expect(e.data).toEqual({ supported_versions: ["0.1", "0.2"] });
  });
});

function createReq(version: string | undefined, id = "c1") {
  return {
    jsonrpc: "2.0" as const,
    id,
    method: "wmp.session.create",
    params: { wmp: version === undefined ? {} : { version }, capabilities_offered: {}, security: { mode: "tls" } },
  };
}

function responder(supported?: string[], caps: Record<string, unknown> = {}) {
  const t = new MockTransport();
  const handler: Handler = {
    onSessionCreate: vi.fn(async () => ({ wmp: { version: "" , session_id: "ses-abc" }, capabilities: caps, security: { mode: "tls" } })),
    onSessionResume: vi.fn(async () => ({ wmp: { version: "" }, resumed: true, missed_messages: 0, security: { mode: "tls" } })),
  };
  const peer = new Peer(t, { handler, supportedVersions: supported });
  return { t, handler, peer };
}

describe("Peer as responder: version negotiation", () => {
  it("answers with the negotiated version (highest not above the offer)", async () => {
    const { t, handler } = responder(["0.1", "0.3"]);
    t.receive(createReq("0.2"));
    await settle();
    const r = t.sent[0] as Response;
    expect((r.result as { wmp: { version: string } }).wmp.version).toBe("0.1");
    expect(handler.onSessionCreate).toHaveBeenCalled();
  });

  it("refuses an unsupported version with -31013 and supported_versions, before the handler", async () => {
    const { t, handler } = responder(["0.1"]);
    t.receive(createReq("1.0"));
    await settle();
    const r = t.sent[0] as Response;
    expect(r.error).toEqual({ code: -31013, message: "Version not supported", data: { supported_versions: ["0.1"] } });
    expect(handler.onSessionCreate).not.toHaveBeenCalled();
  });

  it("refuses a version below the responder minimum (never selects above the offer)", async () => {
    const { t } = responder(["0.2"]);
    t.receive(createReq("0.1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31013);
  });

  it("refuses a malformed or absent version with -32602", async () => {
    for (const v of ["v0.1", "0.1.0", "0.01", "", undefined]) {
      const { t } = responder(["0.1"]);
      t.receive(createReq(v));
      await settle();
      expect((t.sent[0] as Response).error, String(v)).toEqual({ code: -32602, message: "Invalid params" });
    }
  });

  it("negotiates session.resume too", async () => {
    const { t, handler } = responder(["0.1"]);
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "2.0" }, session_id: "ses-abc", resumption_token: "t" } });
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31013);
    expect(handler.onSessionResume).not.toHaveBeenCalled();
  });

  it("answers with the negotiated version when the handler set the same one", async () => {
    const t = new MockTransport();
    new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "0.1", session_id: "s" }, security: { mode: "tls" } }) } });
    t.receive(createReq("0.1"));
    await settle();
    expect(((t.sent[0] as Response).result as { wmp: { version: string } }).wmp.version).toBe("0.1");
  });
});

describe("Peer as client: version acceptance", () => {
  async function create(offered: string[] | undefined, selected: string) {
    const t = new MockTransport();
    const peer = new Peer(t, { supportedVersions: offered });
    const p = peer.createSession({});
    await settle();
    const req = t.sent[0] as { id: string; params: { wmp: { version: string } } };
    t.receive({ jsonrpc: "2.0", id: req.id, result: { wmp: { version: selected, session_id: "ses-1" }, security: { mode: "tls" } } });
    return { p, offeredVersion: req.params.wmp.version, peer };
  }

  it("offers the highest supported version", async () => {
    const { p, offeredVersion } = await create(["0.1", "0.3", "0.2"], "0.3");
    expect(offeredVersion).toBe("0.3");
    await p;
  });

  it("accepts a selected version below the offer that it supports", async () => {
    const { p, peer } = await create(["0.1", "0.3"], "0.1");
    await expect(p).resolves.toBeDefined();
    expect(peer.session).toBe("ses-1");
  });

  it("refuses a selected version it does not support, one above its offer, or a different major", async () => {
    for (const [supported, selected] of [[["0.1"], "0.2"], [["0.1", "0.3"], "0.2"], [["0.1"], "1.0"], [["0.1"], "0.0"]] as [string[], string][]) {
      const { p } = await create(supported, selected);
      await expect(p, `${supported} -> ${selected}`).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
    }
  });

  it("default supports 0.1 only", () => {
    expect(SUPPORTED_VERSIONS).toEqual(["0.1"]);
  });
});

function flowStart(type: string) {
  return {
    jsonrpc: "2.0" as const,
    id: "f1",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1" }, flow_type: type, flow_id: "flow-1", params: {} },
  };
}

describe("unknown flow type is -31005 {unsupported}", () => {
  it("when nobody implements it", async () => {
    const t = new MockTransport();
    new Peer(t, {});
    t.receive(flowStart("no-such-flow"));
    await settle();
    expect((t.sent[0] as Response).error).toEqual({ code: -31005, message: "Capability not supported", data: { unsupported: "no-such-flow" } });
  });

  it("when the handler answers method-not-found", async () => {
    const t = new MockTransport();
    new Peer(t, { handler: { onFlowStart: async () => { throw new WMPError(ErrorCode.MethodNotFound, "x"); } } });
    t.receive(flowStart("no-such-flow"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("but a handler's own error passes through", async () => {
    const t = new MockTransport();
    new Peer(t, { handler: { onFlowStart: async () => { throw new WMPError(ErrorCode.InvalidParams, "bad"); } } });
    t.receive(flowStart("sign"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-32602);
  });
});

describe("capability gating on FlowHandler", () => {
  async function peerWith(caps: Record<string, unknown> | undefined) {
    const t = new MockTransport();
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    const peer = new Peer(t, {
      handler: caps === undefined ? {} : { onSessionCreate: async () => ({ wmp: { version: "", session_id: "s" }, capabilities: caps, security: { mode: "tls" } }) },
    });
    peer.use(new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }));
    if (caps !== undefined) {
      t.receive(createReq("0.1", "create"));
      await settle();
      t.sent.length = 0;
    }
    return { t, onVCIStart };
  }

  it("refuses a flow type whose capability was not negotiated, before the profile", async () => {
    const { t, onVCIStart } = await peerWith({ messaging: {} });
    t.receive(flowStart("oid4vci"));
    await settle();
    expect((t.sent[0] as Response).error).toEqual({ code: -31005, message: "Capability not supported", data: { unsupported: "oid4vci", capability: "oid4vci" } });
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("admits it once the capability is negotiated", async () => {
    const { t, onVCIStart } = await peerWith({ oid4vci: {} });
    t.receive(flowStart("oid4vci"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("fails closed when no session capabilities are known", async () => {
    const { t, onVCIStart } = await peerWith(undefined);
    t.receive(flowStart("oid4vci"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("gates a client-created session by the capabilities the server granted", async () => {
    const t = new MockTransport();
    const onVCIStart = vi.fn();
    const peer = new Peer(t, {});
    peer.use(new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }));
    const p = peer.createSession({ capabilities: { oid4vci: {} } });
    await settle();
    const req = t.sent[0] as { id: string };
    t.receive({ jsonrpc: "2.0", id: req.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } } });
    await p;
    t.sent.length = 0;
    t.receive(flowStart("oid4vci")); // offered but not granted
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("admits a flow type the server granted to a client-created session", async () => {
    const t = new MockTransport();
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    const peer = new Peer(t, {});
    peer.use(new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }));
    const p = peer.createSession({ capabilities: { oid4vci: {} } });
    await settle();
    const req = t.sent[0] as { id: string };
    t.receive({ jsonrpc: "2.0", id: req.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await p;
    t.sent.length = 0;
    t.receive(flowStart("oid4vci"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("does not gate a handler that declares no requirement", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const startFlow = vi.fn(async (p: { wmp: never; flow_id: string; flow_type: string }) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }));
    peer.use({
      name: "x",
      capabilities: () => [],
      init: () => {},
      flowTypes: () => ["custom"],
      startFlow,
      handleAction: async (p: never) => p,
      handleProgress: () => {},
      handleComplete: () => {},
      handleError: () => {},
    } as never);
    t.receive(flowStart("custom"));
    await settle();
    expect(startFlow).toHaveBeenCalled();
  });
});

describe("WMPError wire form", () => {
  it("toRPCError carries the plain message", () => {
    expect(new WMPError(-31013, "Version not supported", { a: 1 }).toRPCError()).toEqual({ code: -31013, message: "Version not supported", data: { a: 1 } });
  });
});

// ---------------------------------------------------------------------------
// Session lifecycle: versions and the capability cache follow the session
// ---------------------------------------------------------------------------

describe("negotiated state follows the session", () => {
  const vciProfile = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };

  function responderPeer(handler: Handler, supported?: string[]) {
    const t = new MockTransport();
    const peer = new Peer(t, { handler, supportedVersions: supported });
    const { profile, onVCIStart } = vciProfile();
    peer.use(profile);
    return { t, peer, onVCIStart };
  }

  const create = (id: string, version = "0.1") => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version }, security: { mode: "tls" } } });
  const flow = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });

  it("a new session that omits capabilities does not keep the previous grant", async () => {
    let n = 0;
    const { t, onVCIStart } = responderPeer({
      onSessionCreate: async () => (++n === 1
        ? { wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }
        : { wmp: { version: "", session_id: "ses-2" }, security: { mode: "tls" } }),
    });
    t.receive(create("c1"));
    await settle();
    t.receive(create("c2"));
    await settle();
    t.sent.length = 0;
    t.receive(flow());
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("an incoming capability.update changes what later flows may start", async () => {
    let granted: Record<string, unknown> = { oid4vci: {} };
    const { t, onVCIStart } = responderPeer({
      onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
      onCapabilityUpdate: async () => ({ wmp: { version: "0.1" }, capabilities: granted, security: { mode: "tls" } }),
    });
    t.receive(create("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "u1", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } } });
    await settle();
    t.sent.length = 0;
    t.receive(flow("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalledTimes(1);

    granted = {};
    t.receive({ jsonrpc: "2.0", id: "u2", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] } });
    await settle();
    t.sent.length = 0;
    t.receive(flow("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("an outgoing capability.update result refreshes the cache", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const { profile, onVCIStart } = vciProfile();
    peer.use(profile);
    const created = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } } });
    await created;
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(flow("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("closing the session (either side) clears what it granted", async () => {
    const mk = () =>
      responderPeer({ onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) });
    // incoming session.close
    const a = mk();
    a.t.receive(create("c"));
    await settle();
    a.t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1", session_id: "ses-1" }, reason: "complete" } });
    await settle();
    a.t.sent.length = 0;
    a.t.receive(flow("ses-1"));
    await settle();
    expect((a.t.sent[0] as Response).error?.code).toBe(-31005);

    // local closeSession on a client-created session
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const { profile, onVCIStart } = vciProfile();
    peer.use(profile);
    const created = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-9" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await created;
    await peer.closeSession();
    t.sent.length = 0;
    t.receive(flow("ses-9"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("capabilities are bound to the session: a flow naming another session is refused", async () => {
    const { t, onVCIStart } = responderPeer({
      onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
    });
    t.receive(create("c"));
    await settle();
    t.sent.length = 0;
    t.receive(flow("ses-OTHER"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
    t.sent.length = 0;
    t.receive(flow("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
  });

  it("a successful resume that returns capabilities grants them on a fresh peer", async () => {
    const { t, onVCIStart } = responderPeer({
      onSessionResume: async () => ({ wmp: { version: "", session_id: "ses-1" }, resumed: true, missed_messages: 0, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
    });
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-1", resumption_token: "t" } });
    await settle();
    t.sent.length = 0;
    t.receive(flow("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("the responder always answers with the negotiated version and uses it afterwards", async () => {
    const { t, peer } = responderPeer({
      // the handler claims a version above what was negotiated
      onSessionCreate: async () => ({ wmp: { version: "0.3", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
    }, ["0.1", "0.3"]);
    t.receive(create("c", "0.2")); // negotiates 0.1
    await settle();
    expect(((t.sent[0] as Response).result as { wmp: { version: string } }).wmp.version).toBe("0.1");
    t.sent.length = 0;
    // a convenience method of the responder carries the negotiated version
    const { t: t2, peer: peer2 } = responderPeer({ onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }) }, ["0.1", "0.3"]);
    t2.receive(create("c", "0.3"));
    await settle();
    t2.sent.length = 0;
    await peer2.flowProgress("flow-1", "step");
    expect((t2.sent[0] as { params: { wmp: { version: string } } }).params.wmp.version).toBe("0.3");
    void peer;
  });

  it("resume negotiation also answers with the selected version", async () => {
    const { t } = responderPeer({ onSessionResume: async () => ({ wmp: { version: "0.3" }, resumed: true, missed_messages: 0, security: { mode: "tls" } }) }, ["0.1", "0.3"]);
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.2" }, session_id: "s", resumption_token: "t" } });
    await settle();
    expect(((t.sent[0] as Response).result as { wmp: { version: string } }).wmp.version).toBe("0.1");
  });
});

describe("client session version handling", () => {
  async function createdPeer(supported: string[], selected: string) {
    const t = new MockTransport();
    const peer = new Peer(t, { supportedVersions: supported });
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: selected, session_id: "ses-1" }, security: { mode: "tls" }, resumption_token: "rt" } });
    await p;
    t.sent.length = 0;
    return { t, peer };
  }

  it("rejects a create result that names no version, or an empty one", async () => {
    for (const wmp of [{ session_id: "ses-1" }, { session_id: "ses-1", version: "" }]) {
      const t = new MockTransport();
      const peer = new Peer(t, {});
      const p = peer.createSession({});
      await settle();
      t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp, security: { mode: "tls" } } });
      await expect(p).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
      expect(peer.session).toBeUndefined();
    }
  });

  it("closeSession sends the negotiated version, not the library default", async () => {
    const { t, peer } = await createdPeer(["0.1", "0.3"], "0.1");
    await peer.closeSession();
    expect((t.sent[0] as { params: { wmp: { version: string } } }).params.wmp.version).toBe("0.1");

    const b = await createdPeer(["0.1", "0.3"], "0.3");
    await b.peer.closeSession();
    expect((b.t.sent[0] as { params: { wmp: { version: string } } }).params.wmp.version).toBe("0.3");
  });

  it("resume validates the selected version before changing any state", async () => {
    for (const bad of ["0.2", "1.0", ""]) {
      const { t, peer } = await createdPeer(["0.1", "0.3"], "0.3");
      const tokenBefore = peer.token;
      const p = peer.resumeSession();
      await settle();
      t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: bad, session_id: "ses-OTHER" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
      await expect(p, bad).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
      expect(peer.session, bad).toBe("ses-1");
      expect(peer.token, bad).toBe(tokenBefore);
    }
  });

  it("resume accepts a supported version not above the offer and stores it", async () => {
    const { t, peer } = await createdPeer(["0.1", "0.3"], "0.3");
    const p = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await p;
    expect(peer.token).toBe("rt2");
    t.sent.length = 0;
    await peer.closeSession();
    expect((t.sent[0] as { params: { wmp: { version: string } } }).params.wmp.version).toBe("0.1");
  });
});

// ---------------------------------------------------------------------------
// Review round 2: stale results, other sessions, responder identity
// ---------------------------------------------------------------------------

describe("session lifecycle and the capability cache (round 2)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const createdClient = async (caps: Record<string, unknown>, sid = "ses-1") => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: caps, security: { mode: "tls" }, resumption_token: "rt" } });
    await p;
    t.sent.length = 0;
    return { t, peer, ...v };
  };

  it("a late capability response cannot recreate a closed session's grant", async () => {
    const { t, peer, onVCIStart } = await createdClient({});
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    await settle();
    const updId = (t.sent[0] as { id: string }).id;
    await peer.closeSession();
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(startVci());
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("a late capability response for session A does not overwrite session B's grant", async () => {
    const { t, peer, onVCIStart } = await createdClient({}, "ses-A");
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-A" }, add: { oid4vci: {} } });
    await settle();
    const updId = (t.sent[0] as { id: string }).id;
    const b = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-B" }, capabilities: {}, security: { mode: "tls" } } });
    await b;
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(startVci("ses-B"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("a late response from an earlier incarnation of the same session id is ignored too", async () => {
    const { t, peer, onVCIStart } = await createdClient({}, "ses-A");
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-A" }, add: { oid4vci: {} } });
    await settle();
    const updId = (t.sent[0] as { id: string }).id;
    const again = peer.createSession({}); // the same id again: a new incarnation
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-A" }, capabilities: {}, security: { mode: "tls" } } });
    await again;
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(startVci("ses-A"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("an incoming capability.update that names another session does not change this session's grant", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onCapabilityUpdate: async () => ({ wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "u", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-OTHER" }, add: { oid4vci: {} } } });
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("a slow incoming capability.update handler cannot recreate a closed session's grant", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onCapabilityUpdate: async () => {
          await gate;
          return { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "u", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } } });
    await settle();
    t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1", session_id: "ses-1" }, reason: "complete" } });
    await settle();
    release();
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("resume without a version in the result is refused and changes nothing", async () => {
    const { t, peer } = await createdClient({ oid4vci: {} });
    const p = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { session_id: "ses-OTHER" }, resumed: true, missed_messages: 0, resumption_token: "rt2", capabilities: {}, security: { mode: "tls" } } });
    await expect(p).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
    expect(peer.session).toBe("ses-1");
    expect(peer.token).toBe("rt");
  });

  it("resuming a different session without capabilities does not keep the previous grant (client)", async () => {
    const { t, peer, onVCIStart } = await createdClient({ oid4vci: {} });
    const p = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-2" }, resumed: true, missed_messages: 0, security: { mode: "tls" } } });
    await p;
    t.sent.length = 0;
    t.receive(startVci()); // names no session: the cache decides
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("resuming the same session without capabilities keeps its grant (client)", async () => {
    const { t, peer, onVCIStart } = await createdClient({ oid4vci: {} });
    const p = peer.resumeSession();
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, security: { mode: "tls" } } });
    await p;
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("resuming a different session without capabilities does not keep the previous grant (responder)", async () => {
    const t = new MockTransport();
    let n = 0;
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
        onSessionResume: async () => (++n, { wmp: { version: "", session_id: "ses-2" }, resumed: true, missed_messages: 0, security: { mode: "tls" } }),
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-2", resumption_token: "x" } });
    await settle();
    expect(n).toBe(1);
    t.sent.length = 0;
    t.receive(startVci());
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("a capability denial leaves an existing flow's recorded context alone", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const onFlowError = vi.fn();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }),
        onFlowComplete,
        onFlowError,
      },
    });
    peer.use(vci().profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "m", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "match", flow_id: "m1", params: { dcql_query: { credentials: [{ id: "pid" }] } } } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "d", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "oid4vci", flow_id: "m1", params: {} } }); // denied: oid4vci not negotiated
    await settle();
    expect((t.sent.at(-1) as Response).error?.code).toBe(-31005);
    t.receive({ jsonrpc: "2.0", method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "m1", result: { satisfiable: true, claims: { name: "secret" } } } });
    await settle();
    expect(onFlowComplete).not.toHaveBeenCalled(); // still held to the match set
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("the responder knows its session: closeSession sends the close and clears the grant", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    expect(peer.session).toBe("ses-1");
    t.sent.length = 0;
    await peer.closeSession();
    expect((t.sent[0] as { method: string; params: { wmp: { session_id: string } } }).method).toBe("wmp.session.close");
    expect((t.sent[0] as { params: { wmp: { session_id: string } } }).params.wmp.session_id).toBe("ses-1");
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("a responder resume records the session identity", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionResume: async () => ({ wmp: { version: "", session_id: "ses-7" }, resumed: true, missed_messages: 0, security: { mode: "tls" } }) } });
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-7", resumption_token: "x" } });
    await settle();
    expect(peer.session).toBe("ses-7");
  });

  it("a delayed close for another session does not strip the current session's grant", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-B" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1", session_id: "ses-A" }, reason: "complete" } });
    await settle();
    expect(peer.session).toBe("ses-B");
    t.sent.length = 0;
    t.receive(startVci("ses-B"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(v.onVCIStart).toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Review round 3: ordering, identity, stale resumes, close races
// ---------------------------------------------------------------------------

describe("capability and session races (round 3)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const client = async (caps: Record<string, unknown>, sid = "ses-1") => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    const v = vci();
    peer.use(v.profile);
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: caps, security: { mode: "tls" }, resumption_token: "rt1" } });
    await p;
    t.sent.length = 0;
    return { t, peer, lost, ...v };
  };

  it("an older capability.list snapshot that arrives after a newer update cannot widen the grant back (outgoing)", async () => {
    const { t, peer, onVCIStart } = await client({ oid4vci: {} });
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] });
    await settle();
    expect(t.sent.map((m) => (m as { method: string }).method)).toEqual(["wmp.capability.list", "wmp.capability.update"]); // no lock: both go out
    const [listId, updId] = [(t.sent[0] as { id: string }).id, (t.sent[1] as { id: string }).id];
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } }); // the revocation answers first
    t.receive({ jsonrpc: "2.0", id: listId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // the older snapshot, late
    await Promise.all([list, upd]);
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("a snapshot requested at the current revision is the latest word and can widen", async () => {
    const { t, peer, onVCIStart } = await client({});
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });

  it("a revocation that arrives as an incoming update is not undone by a late outgoing snapshot (both directions)", async () => {
    let granted: Record<string, unknown> = { oid4vci: {} };
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
        onCapabilityUpdate: async () => ({ wmp: { version: "0.1" }, capabilities: granted, security: { mode: "tls" } }),
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.sent.length = 0;
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } }); // outgoing, pending
    await settle();
    granted = {};
    t.receive({ jsonrpc: "2.0", id: "u", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] } }); // incoming revocation
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.find((m) => (m as { method?: string }).method === "wmp.capability.list") as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await list;
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("a same-session resume snapshot requested before a revocation cannot restore the grant", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: { onCapabilityUpdate: async () => ({ wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } }) },
    });
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" }, resumption_token: "rt" } });
    await c;
    t.sent.length = 0;
    const resume = peer.resumeSession(); // snapshot requested now
    await settle();
    t.receive({ jsonrpc: "2.0", id: "u", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] } }); // revoked meanwhile
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, capabilities: { oid4vci: {} }, resumption_token: "rt2", security: { mode: "tls" } } });
    await resume;
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("two incoming capability handlers finishing out of order cannot widen the grant", async () => {
    const gates: (() => void)[] = [];
    let call = 0;
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
        onCapabilityList: async () => {
          const mine = ++call;
          if (mine === 1) await new Promise<void>((r) => gates.push(r)); // the first is slow and answers with the old grant; the second waits for it
          return { wmp: { version: "0.1" }, capabilities: mine === 1 ? { oid4vci: {} } : {}, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l1", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l2", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } }); // newer, fast: empty
    await settle();
    gates[0](); // the older one finishes last
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("a grant without a session identity admits nothing", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) as never } });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-ANY"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    t.sent.length = 0;
    t.receive(startVci());
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("a capability result for the session the REQUEST names is not cached as the current session's grant", async () => {
    const { t, peer, onVCIStart } = await client({}, "ses-A");
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-B" } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await list;
    t.sent.length = 0;
    t.receive(startVci("ses-A"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("a resume that finishes after the session was closed does not bring it back (and is not reported as a loss)", async () => {
    const { t, peer, lost } = await client({ oid4vci: {} });
    t.emitEvent("gap");
    await settle();
    const resume = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    await peer.closeSession();
    t.receive({ jsonrpc: "2.0", id: resume.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await settle(30);
    expect(peer.session).toBeUndefined();
    expect(peer.token).toBe("rt1");
    expect(lost).toHaveLength(0);
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("a responder resume that finishes after the session was replaced installs nothing", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    let n = 0;
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: `ses-new` }, capabilities: {}, security: { mode: "tls" } }),
        onSessionResume: async () => {
          n++;
          await gate;
          return { wmp: { version: "", session_id: "ses-old" }, resumed: true, missed_messages: 0, capabilities: { oid4vci: {} }, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-old", resumption_token: "x" } });
    await settle();
    t.receive(mkCreate("c")); // the peer now serves another session
    await settle();
    release();
    await settle();
    expect(n).toBe(1);
    expect(peer.session).toBe("ses-new");
    t.sent.length = 0;
    t.receive(startVci("ses-old"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("an unsuccessful resume result changes nothing and recovery reports the loss", async () => {
    const { t, peer, lost, onVCIStart } = await client({ oid4vci: {} });
    t.emitEvent("gap");
    await settle();
    const resume = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    t.receive({ jsonrpc: "2.0", id: resume.id, result: { wmp: { version: "0.1", session_id: "ses-OTHER" }, resumed: false, missed_messages: 0, resumption_token: "rt2", capabilities: {}, security: { mode: "tls" } } });
    await settle(30);
    expect(lost).toHaveLength(1);
    expect(peer.session).toBe("ses-1");
    expect(peer.token).toBe("rt1");
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    // The session could not be continued: its grant is invalidated, gated flows fail closed.
    expect(onVCIStart).not.toHaveBeenCalled();
    expect((t.sent[0] as Response).error).toBeDefined();
  });

  it("a responder's unsuccessful resume installs no session state", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionResume: async () => ({ wmp: { version: "", session_id: "ses-9" }, resumed: false, missed_messages: 0, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) } });
    const v = vci();
    peer.use(v.profile);
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-9", resumption_token: "x" } });
    await settle();
    expect(peer.session).toBeUndefined();
    t.sent.length = 0;
    t.receive(startVci("ses-9"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("closeSession does not clear a replacement session established while the close was being sent", async () => {
    const { t, peer, onVCIStart } = await client({ oid4vci: {} }, "ses-A");
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (m) => {
      if ((m as { method?: string }).method === "wmp.session.close") await gate;
      await realSend(m);
    };
    const closing = peer.closeSession();
    await settle();
    const created = peer.createSession({});
    await settle();
    const createReq = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.create") as { id: string };
    t.receive({ jsonrpc: "2.0", id: createReq.id, result: { wmp: { version: "0.1", session_id: "ses-B" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await created;
    release();
    await closing;
    expect(peer.session).toBe("ses-B");
    t.sent.length = 0;
    t.receive(startVci("ses-B"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(onVCIStart).toHaveBeenCalled();
  });
});

describe("session identity details (round 4)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });

  it("the cached grant is a copy: mutating the object the handler returned changes nothing", async () => {
    const granted: Record<string, unknown> = { oid4vci: {} };
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: granted, security: { mode: "tls" } }) } });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    delete granted.oid4vci; // later mutation of the caller's object
    granted.other = {};
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined(); // still granted
    expect(v.onVCIStart).toHaveBeenCalled();

    // and the other way: adding to the object does not grant
    const t2 = new MockTransport();
    const g2: Record<string, unknown> = {};
    const peer2 = new Peer(t2, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: g2, security: { mode: "tls" } }) } });
    const v2 = vci();
    peer2.use(v2.profile);
    t2.receive(mkCreate("c"));
    await settle();
    g2.oid4vci = {};
    t2.sent.length = 0;
    t2.receive(startVci("ses-1"));
    await settle();
    expect((t2.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("resuming the same session while closeSession is sending does not defeat the close", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const created = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" }, resumption_token: "rt" } });
    await created;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (m) => {
      if ((m as { method?: string }).method === "wmp.session.close") await gate;
      await realSend(m);
    };
    const closing = peer.closeSession();
    await settle();
    const resumed = peer.resumeSession(); // the same session, while the close is in flight
    await settle();
    const resumeReq = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    t.receive({ jsonrpc: "2.0", id: resumeReq.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, capabilities: { oid4vci: {} }, resumption_token: "rt2", security: { mode: "tls" } } });
    await resumed;
    release();
    await closing;
    expect(peer.session).toBeUndefined();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005); // the grant is gone
  });

  it("a slow incoming create that outlives a later one is refused and cannot overwrite it", async () => {
    const gates: (() => void)[] = [];
    let n = 0;
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => {
          const mine = ++n;
          if (mine === 1) await new Promise<void>((r) => gates.push(r));
          return { wmp: { version: "", session_id: `ses-${mine}` }, capabilities: mine === 1 ? { oid4vci: {} } : {}, security: { mode: "tls" } };
        },
      },
    });
    t.receive(mkCreate("c1"));
    await settle();
    t.receive(mkCreate("c2"));
    await settle();
    gates[0]();
    await settle(30);
    expect(peer.session).toBe("ses-2"); // the later create is the one installed
  });

  it("the responder binds the transport to the session it installs (create and resume)", async () => {
    const t = new MockTransport() as MockTransport & { setSessionId?: (id: string) => void };
    const bound: string[] = [];
    t.setSessionId = (id) => void bound.push(id);
    new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onSessionResume: async () => ({ wmp: { version: "", session_id: "ses-2" }, resumed: true, missed_messages: 0, security: { mode: "tls" } }),
      },
    });
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-2", resumption_token: "x" } });
    await settle();
    expect(bound).toEqual(["ses-1", "ses-2"]);
  });

  it("a replaced session's resumption token is not used for the new one", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e), handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-N" }, capabilities: {}, security: { mode: "tls" } }) } });
    const created = peer.createSession({}); // our own session, with a token
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" }, resumption_token: "OLD" } });
    await created;
    expect(peer.token).toBe("OLD");
    t.receive(mkCreate("c")); // an incoming create replaces it
    await settle();
    expect(peer.token).toBeUndefined();
    t.sent.length = 0;
    t.emitEvent("gap");
    await settle(30);
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume")).toHaveLength(0); // never presents OLD for ses-N
    expect(lost).toHaveLength(1);
  });

  it("a responder's resume of another session drops the old session's markers, of the same one keeps them", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    let target = "ses-1";
    new Peer(t, {
      handler: {
        onFlowComplete,
        onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }),
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onSessionResume: async () => ({ wmp: { version: "", session_id: target }, resumed: true, missed_messages: 0, security: { mode: "tls" } }),
      },
    });
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "sf", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f", params: {} } }); // a flow this peer knows
    await settle();
    const done = { jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "f", result: { credentials: [] } } };
    t.receive(done);
    await settle();
    const resume = async (id: string) => {
      t.receive({ jsonrpc: "2.0", id, method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: target, resumption_token: "x" } });
      await settle();
    };
    await resume("r1"); // the same session
    t.receive(done);
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    target = "ses-2";
    await resume("r2"); // another session
    t.receive(done);
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
  });

  it("terminal markers are dropped when the resumed session differs and kept when it is the same", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const peer = new Peer(t, { handler: { onFlowComplete } });
    const created = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" }, resumption_token: "rt" } });
    await created;
    peer.startFlow("sign", "f", {}).catch(() => {}); // a flow this peer knows
    await settle();
    const done = { jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "f", result: { credentials: [] } } };
    t.receive(done);
    await settle();
    const resumeTo = async (sid: string) => {
      const p = peer.resumeSession();
      await settle();
      t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, resumed: true, missed_messages: 0, security: { mode: "tls" } } });
      await p;
    };
    await resumeTo("ses-1"); // the same session: a re-sent terminal is still a repeat
    t.receive(done);
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    await resumeTo("ses-2"); // another session: the old session's markers are gone
    t.receive(done);
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
  });
});

describe("session establishment edge cases (round 8)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: unknown, extra: Record<string, unknown> = {}) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid !== undefined ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {}, ...extra },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const codeOf = (m: unknown) => (m as Response).error?.code;

  it("a slow incoming create refused as superseded does not overwrite, and answers with an error", async () => {
    const gates: (() => void)[] = [];
    let n = 0;
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => {
          const mine = ++n;
          if (mine === 1) await new Promise<void>((r) => gates.push(r));
          return { wmp: { version: "", session_id: `ses-${mine}` }, capabilities: {}, security: { mode: "tls" } };
        },
      },
    });
    t.receive(mkCreate("c1"));
    await settle();
    t.receive(mkCreate("c2"));
    await settle();
    gates[0]();
    await settle(30);
    expect(peer.session).toBe("ses-2");
    expect(codeOf(t.sent.find((m) => (m as { id?: string }).id === "c1"))).toBe(-31000); // not "success"
    expect((t.sent.find((m) => (m as { id?: string }).id === "c2") as Response).error).toBeUndefined();
  });

  it("a slow incoming create that finishes after a local createSession installed another session is refused", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => {
          await gate;
          return { wmp: { version: "", session_id: "ses-incoming" }, capabilities: {}, security: { mode: "tls" } };
        },
      },
    });
    t.receive(mkCreate("in"));
    await settle();
    const local = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.find((m) => (m as { method?: string }).method === "wmp.session.create") as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-local" }, capabilities: {}, security: { mode: "tls" }, resumption_token: "rt" } });
    await local;
    release();
    await settle(30);
    expect(peer.session).toBe("ses-local");
    expect(peer.token).toBe("rt");
  });

  it("a create result without a usable session id is refused before any state changes", async () => {
    for (const bad of [undefined, "", null, 5]) {
      const t = new MockTransport();
      let first = true;
      const peer = new Peer(t, {
        handler: {
          onSessionCreate: async () => {
            if (first) {
              first = false;
              return { wmp: { version: "", session_id: "ses-good" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } };
            }
            return { wmp: { version: "", ...(bad === undefined ? {} : { session_id: bad }) }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } as never;
          },
        },
      });
      const v = vci();
      peer.use(v.profile);
      t.receive(mkCreate("c1"));
      await settle();
      t.receive(mkCreate("c2"));
      await settle();
      expect(codeOf(t.sent[1]), String(bad)).toBe(-32603);
      expect(peer.session, String(bad)).toBe("ses-good"); // untouched
      t.sent.length = 0;
      t.receive(startVci("ses-good"));
      await settle();
      expect((t.sent[0] as Response).error, String(bad)).toBeUndefined(); // the good session's grant survives
    }
  });

  it("a stale successful resume on the responder is an error, not resumed:true", async () => {
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-new" }, capabilities: {}, security: { mode: "tls" } }),
        onSessionResume: async () => {
          await gate;
          return { wmp: { version: "", session_id: "ses-old" }, resumed: true, missed_messages: 0, security: { mode: "tls" } };
        },
      },
    });
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-old", resumption_token: "x" } });
    await settle();
    t.receive(mkCreate("c")); // the session is replaced meanwhile
    await settle();
    release();
    await settle(30);
    const resumeAnswer = t.sent.find((m) => (m as { id?: string }).id === "r") as Response;
    expect(resumeAnswer.error?.code).toBe(-31000);
    expect(resumeAnswer.result).toBeUndefined();
    expect(peer.session).toBe("ses-new");
  });

  it("a present session id of the wrong type or value never uses the session's grant", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }) } });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    for (const bad of [null, 5, "", "ses-2", {}, false]) {
      t.sent.length = 0;
      t.receive(startVci(bad));
      await settle();
      expect(codeOf(t.sent[0]), JSON.stringify(bad)).toBe(-31005);
    }
    expect(v.onVCIStart).not.toHaveBeenCalled();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    t.sent.length = 0;
    t.receive({ ...startVci(), id: "f2", params: { wmp: { version: "0.1" }, flow_type: "oid4vci", flow_id: "flow-2", params: {} } }); // an omitted id is allowed
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
  });

  it("overlapping createSession calls: the newest request wins whatever order the answers arrive in", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const a = peer.createSession({});
    const b = peer.createSession({});
    await settle();
    const [ra, rb] = t.sent.map((m) => m as { id: string });
    const answer = (id: string, sid: string, token: string) => t.receive({ jsonrpc: "2.0", id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: token } });
    answer(rb.id, "ses-B", "rtB"); // the newer answer first
    await b;
    answer(ra.id, "ses-A", "rtA"); // the older one later
    await expect(a).rejects.toBeDefined();
    expect(peer.session).toBe("ses-B");
    expect(peer.token).toBe("rtB");
    // and the natural order still works
    const c = peer.createSession({});
    const d = peer.createSession({});
    await settle();
    const [, , rc, rd] = t.sent.map((m) => m as { id: string });
    answer(rc.id, "ses-C", "rtC");
    await c;
    answer(rd.id, "ses-D", "rtD");
    await d;
    expect(peer.session).toBe("ses-D");
  });

  it("fails before sending when there is no valid supported version to offer", async () => {
    for (const supported of [[], ["bogus"], ["0.01", "v1"]]) {
      const t = new MockTransport();
      const peer = new Peer(t, { supportedVersions: supported });
      await expect(peer.createSession({}), JSON.stringify(supported)).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
      expect(t.sent).toHaveLength(0);
    }
  });

  it("flow.start without a real flow_type or flow_id is -32602, not an unsupported flow", async () => {
    const t = new MockTransport();
    new Peer(t, {});
    const bad = [
      { flow_id: "f" },
      { flow_type: 5, flow_id: "f" },
      { flow_type: "", flow_id: "f" },
      { flow_type: "x" },
      { flow_type: "x", flow_id: 5 },
      { flow_type: "x", flow_id: "" },
    ];
    for (const p of bad) {
      t.sent.length = 0;
      t.receive({ jsonrpc: "2.0", id: "s", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, ...p } } as never);
      await settle();
      expect((t.sent[0] as Response).error, JSON.stringify(p)).toMatchObject({ code: -32602, message: "Invalid params" });
    }
  });
});

describe("version helpers follow the negotiated version (round 8)", () => {
  it("buildVCIFlowStart takes the session's version, defaulting to 0.1", async () => {
    const { buildVCIFlowStart } = await import("../src/openid4x.js");
    expect(buildVCIFlowStart("s", "f", { offer: "openid-credential-offer://x" }).wmp.version).toBe("0.1");
    expect(buildVCIFlowStart("s", "f", { offer: "openid-credential-offer://x" }, undefined, "0.3").wmp.version).toBe("0.3");
  });

  it("the relay answers a registration in the version of the request", async () => {
    const { Relay } = await import("../src/relay.js");
    const relay = new Relay({} as never);
    const reg = async (version: unknown) => (await relay.handleMethod("wmp.relay.register", { wmp: { version, sender: "x509:san:dns:a.example" } })) as { wmp: { version: string } };
    expect((await reg("0.3")).wmp.version).toBe("0.3");
    expect((await reg("0.1")).wmp.version).toBe("0.1");
    expect((await reg("nonsense")).wmp.version).toBe("0.1");
    expect((await reg(undefined)).wmp.version).toBe("0.1");
  });
});

describe("session installation order, generic API, grant refresh (round 9)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const createAnswer = (id: string, sid: string, token = "rt", caps: Record<string, unknown> = {}) => ({ jsonrpc: "2.0" as const, id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: caps, security: { mode: "tls" }, resumption_token: token } });

  it("an outgoing create issued before an incoming create installed another session is stale, one issued after wins", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-in" }, capabilities: {}, security: { mode: "tls" } }) } });
    const out = peer.createSession({});
    out.catch(() => {});
    await settle();
    const outId = (t.sent[0] as { id: string }).id;
    t.receive(mkCreate("in")); // an incoming create installs ses-in
    await settle();
    expect(peer.session).toBe("ses-in");
    t.receive(createAnswer(outId, "ses-out-old")); // the earlier outgoing answer, late
    await expect(out).rejects.toBeDefined();
    expect(peer.session).toBe("ses-in");
    const later = peer.createSession({}); // issued after the install: it wins
    await settle();
    t.receive(createAnswer((t.sent.at(-1) as { id: string }).id, "ses-out-new", "rtNew"));
    await later;
    expect(peer.session).toBe("ses-out-new");
    expect(peer.token).toBe("rtNew");
  });

  it("an incoming resume installing a session also outdates an earlier outgoing create", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onSessionResume: async () => ({ wmp: { version: "", session_id: "ses-r" }, resumed: true, missed_messages: 0, security: { mode: "tls" } }) } });
    const out = peer.createSession({});
    out.catch(() => {});
    await settle();
    const outId = (t.sent[0] as { id: string }).id;
    t.receive({ jsonrpc: "2.0", id: "r", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-r", resumption_token: "x" } });
    await settle();
    t.receive(createAnswer(outId, "ses-out"));
    await expect(out).rejects.toBeDefined();
    expect(peer.session).toBe("ses-r");
  });

  it("notify('wmp.session.close') ends the session like closeSession()", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1", "rt", { oid4vci: {} }));
    await c;
    await peer.notify("wmp.session.close", { wmp: { version: "0.1", session_id: "ses-1" }, reason: "complete" });
    expect(peer.session).toBeUndefined();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("a generic close naming another session, or one overtaken by a replacement, leaves the session alone", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1"));
    await c;
    await peer.notify("wmp.session.close", { wmp: { version: "0.1", session_id: "ses-OTHER" } });
    expect(peer.session).toBe("ses-1");
    // a replacement is established while the close is being sent
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const realSend = t.send.bind(t);
    t.send = async (m) => {
      if ((m as { method?: string }).method === "wmp.session.close") await gate;
      await realSend(m);
    };
    const closing = peer.notify("wmp.session.close", { wmp: { version: "0.1", session_id: "ses-1" } });
    await settle();
    const again = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent.find((m) => (m as { method?: string }).method === "wmp.session.create" && (m as { id: string }).id !== (t.sent[0] as { id: string }).id) as { id: string }).id, "ses-2"));
    await again;
    release();
    await closing;
    expect(peer.session).toBe("ses-2");
  });

  it("the transport's session binding is cleared when a session ends", async () => {
    const t = new MockTransport() as MockTransport & { clearSession?: () => void };
    const cleared: number[] = [];
    t.clearSession = () => void cleared.push(1);
    const peer = new Peer(t, { handler: { onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-in" }, capabilities: {}, security: { mode: "tls" } }) } });
    t.receive(mkCreate("in"));
    await settle();
    expect(cleared).toHaveLength(0);
    t.receive({ jsonrpc: "2.0", method: "wmp.session.close", params: { wmp: { version: "0.1", session_id: "ses-in" } } });
    await settle();
    expect(cleared).toHaveLength(1);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent.at(-1) as { id: string }).id, "ses-2"));
    await c;
    await peer.closeSession();
    expect(cleared).toHaveLength(2);
  });

  it("the generic call API installs a created session and validates its version", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const p = peer.call("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-g", "rtg", { oid4vci: {} }));
    await p;
    expect(peer.session).toBe("ses-g");
    expect(peer.token).toBe("rtg");
    t.sent.length = 0;
    t.receive(startVci("ses-g"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(v.onVCIStart).toHaveBeenCalled();

    // a version this peer does not speak is refused and installs nothing
    const t2 = new MockTransport();
    const peer2 = new Peer(t2, {});
    const bad = peer2.call("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    await settle();
    t2.receive({ jsonrpc: "2.0", id: (t2.sent[0] as { id: string }).id, result: { wmp: { version: "0.9", session_id: "ses-x" }, capabilities: {}, security: { mode: "tls" } } });
    await expect(bad).rejects.toMatchObject({ code: ErrorCode.VersionNotSupported });
    expect(peer2.session).toBeUndefined();
  });

  it("the generic call API installs a resumed session too", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const p = peer.call("wmp.session.resume", { wmp: { version: "0.1" }, session_id: "ses-r", resumption_token: "x" });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-r" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await p;
    expect(peer.session).toBe("ses-r");
    expect(peer.token).toBe("rt2");
  });

  it("a stale (older) outgoing snapshot narrows, and a fresh capability.list restores what is really granted", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1", "rt", {}));
    await c;
    t.sent.length = 0;
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } }); // requested while the grant is empty
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    await settle();
    const [listId, updId] = [(t.sent[0] as { id: string }).id, (t.sent[1] as { id: string }).id];
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // the grant is now oid4vci
    t.receive({ jsonrpc: "2.0", id: listId, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } }); // the older, empty snapshot arrives late
    await Promise.all([list, upd]);
    await settle();
    // the stale answer narrowed the grant and a fresh list was requested
    const refresh = t.sent.filter((m) => (m as { method?: string }).method === "wmp.capability.list")[1] as { id: string };
    expect(refresh).toBeDefined();
    t.receive({ jsonrpc: "2.0", id: refresh.id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined(); // the legitimately granted capability is back
    expect(v.onVCIStart).toHaveBeenCalled();
  });

  it("the refresh never widens beyond what the peer answers (a refresh that fails leaves the grant narrowed)", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1", "rt", { oid4vci: {} }));
    await c;
    t.sent.length = 0;
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] });
    await settle();
    const [listId, updId] = [(t.sent[0] as { id: string }).id, (t.sent[1] as { id: string }).id];
    t.receive({ jsonrpc: "2.0", id: updId, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } });
    t.receive({ jsonrpc: "2.0", id: listId, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await Promise.all([list, upd]);
    await settle();
    const refresh = t.sent.filter((m) => (m as { method?: string }).method === "wmp.capability.list")[1] as { id: string };
    t.receive({ jsonrpc: "2.0", id: refresh.id, error: { code: -32601, message: "no" } }); // cannot answer
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("a newer incoming handler's grant is not lost to an older one finishing late", async () => {
    const gates: (() => void)[] = [];
    let n = 0;
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onCapabilityList: async () => {
          const mine = ++n;
          if (mine === 1) await new Promise<void>((r) => gates.push(r)); // older, slow: knows nothing
          return { wmp: { version: "0.1" }, capabilities: mine === 1 ? {} : { oid4vci: {} }, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l1", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l2", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } }); // newer, fast: grants oid4vci
    await settle();
    gates[0](); // the older one finishes last
    await settle();
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    expect(v.onVCIStart).toHaveBeenCalled();
  });
});

describe("capability ordering, generic session edge cases, refresh queue (round 10)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const createAnswer = (id: string, sid: string, token?: string, caps: Record<string, unknown> = {}, version = "0.1") => ({ jsonrpc: "2.0" as const, id, result: { wmp: { version, session_id: sid }, capabilities: caps, security: { mode: "tls" }, ...(token ? { resumption_token: token } : {}) } });
  const capsList = (t: MockTransport) => t.sent.filter((m) => (m as { method?: string }).method === "wmp.capability.list") as { id: string }[];

  it("a slow incoming revocation and a list that ran before it finished cannot leave the revoked capability admitted", async () => {
    let granted: Record<string, unknown> = { oid4vci: {} };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
        onCapabilityUpdate: async () => {
          await gate; // the revocation takes a while
          granted = {};
          return { wmp: { version: "0.1" }, capabilities: granted, security: { mode: "tls" } };
        },
        onCapabilityList: async () => ({ wmp: { version: "0.1" }, capabilities: granted, security: { mode: "tls" } }), // reports the CURRENT state
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "u", method: "wmp.capability.update", params: { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } }); // waits for the update
    await settle();
    release();
    await settle(30);
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("an incoming handler's result cannot undo a newer change made through the outgoing direction", async () => {
    let granted: Record<string, unknown> = { oid4vci: {} };
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } }),
        onCapabilityList: async () => {
          const snapshot = { ...granted }; // captured now...
          await gate; // ...answered later
          return { wmp: { version: "0.1" }, capabilities: snapshot, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } });
    await settle();
    t.sent.length = 0;
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } }); // revoked through the outgoing direction
    await upd;
    granted = {}; // the revocation reached this peer's own authority too
    release(); // the delayed incoming list now returns its old snapshot
    await settle(30);
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(v.onVCIStart).not.toHaveBeenCalled();
  });

  it("generic create/resume require a valid offer and a compatible selection: 'bogus' is not a version", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { supportedVersions: ["bogus", "0.1"] });
    const p = peer.call("wmp.session.create", { wmp: { version: "bogus" }, security: { mode: "tls" } });
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-b", "rt", {}, "bogus"));
    await expect(p).rejects.toMatchObject({ code: -32602 });
    expect(peer.session).toBeUndefined();

    const r = peer.call("wmp.session.resume", { wmp: { version: "bogus" }, session_id: "ses-b", resumption_token: "x" });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "bogus", session_id: "ses-b" }, resumed: true, missed_messages: 0, security: { mode: "tls" } } });
    await expect(r).rejects.toMatchObject({ code: -32602 });
    expect(peer.session).toBeUndefined();

    // no offer at all
    const t2 = new MockTransport();
    const peer2 = new Peer(t2, {});
    const q = peer2.call("wmp.session.create", { security: { mode: "tls" } });
    await settle();
    t2.receive(createAnswer((t2.sent[0] as { id: string }).id, "ses-x", "rt"));
    await expect(q).rejects.toMatchObject({ code: -32602 });
    expect(peer2.session).toBeUndefined();
  });

  it("a successful create replaces the resumption token, clearing it when the new session has none", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const a = peer.call("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-A", "rtA"));
    await a;
    expect(peer.token).toBe("rtA");
    const b = peer.call("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    await settle();
    t.receive(createAnswer((t.sent[1] as { id: string }).id, "ses-B")); // no token
    await b;
    expect(peer.session).toBe("ses-B");
    expect(peer.token).toBeUndefined();
    const lost: Error[] = [];
    const peer2 = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    void peer2;
  });

  it("a generic resume that leaves out wmp.session_id uses the requested one (fresh peer, and switching A to B)", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const r1 = peer.call("wmp.session.resume", { wmp: { version: "0.1" }, session_id: "ses-r", resumption_token: "x" });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, resumed: true, missed_messages: 0, capabilities: { oid4vci: {} }, resumption_token: "rt1", security: { mode: "tls" } } });
    await r1;
    expect(peer.session).toBe("ses-r");
    t.sent.length = 0;
    t.receive(startVci("ses-r"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined();
    // switching to another session: the capabilities belong to B, not to A
    t.sent.length = 0;
    const r2 = peer.call("wmp.session.resume", { wmp: { version: "0.1" }, session_id: "ses-B", resumption_token: "y" });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, resumed: true, missed_messages: 0, capabilities: {}, security: { mode: "tls" } } });
    await r2;
    expect(peer.session).toBe("ses-B");
    t.sent.length = 0;
    t.receive(startVci("ses-B"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005); // B's (empty) grant, not A's
  });

  it("resuming another session drops the old token even when the new session returns none", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const a = peer.call("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-A", "rtA"));
    await a;
    const r = peer.call("wmp.session.resume", { wmp: { version: "0.1" }, session_id: "ses-B", resumption_token: "y" });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-B" }, resumed: true, missed_messages: 0, security: { mode: "tls" } } }); // no token
    await r;
    expect(peer.session).toBe("ses-B");
    expect(peer.token).toBeUndefined();
  });

  it("a refresh requested while another is in flight runs after it", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1", "rt", {}));
    await c;
    t.sent.length = 0;
    // two operations whose answers arrive stale, one after the other
    const l1 = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const u1 = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    const l2 = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    await settle();
    const [l1id, u1id, l2id] = t.sent.map((m) => (m as { id: string }).id);
    t.receive({ jsonrpc: "2.0", id: u1id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // grants
    t.receive({ jsonrpc: "2.0", id: l1id, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } }); // stale -> narrows, refresh #1 in flight
    await settle();
    expect(capsList(t)).toHaveLength(3); // l1, l2 and the first refresh
    // another stale answer arrives while refresh #1 is still unanswered
    t.receive({ jsonrpc: "2.0", id: l2id, result: { wmp: { version: "0.1" }, capabilities: { other: {} }, security: { mode: "tls" } } }); // stale and different from the cache
    await settle();
    expect(capsList(t)).toHaveLength(3); // the second refresh waits for the first
    const refresh1 = capsList(t)[2];
    t.receive({ jsonrpc: "2.0", id: refresh1.id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await settle(30);
    expect(capsList(t).length).toBeGreaterThanOrEqual(4); // the queued refresh ran after it
  });
});

describe("stale snapshots, refresh sources (round 11)", () => {
  const vci = () => {
    const onVCIStart = vi.fn(async (p: { wmp: unknown; flow_id: string; flow_type: string }) => ({ wmp: p.wmp as never, flow_id: p.flow_id, flow_type: p.flow_type }));
    return { profile: new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart }), onVCIStart };
  };
  const startVci = (sid?: string) => ({
    jsonrpc: "2.0" as const,
    id: "f",
    method: "wmp.flow.start",
    params: { wmp: { version: "0.1", ...(sid ? { session_id: sid } : {}) }, flow_type: "oid4vci", flow_id: "flow-1", params: {} },
  });
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const createAnswer = (id: string, sid: string, caps: Record<string, unknown> = {}) => ({ jsonrpc: "2.0" as const, id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: caps, security: { mode: "tls" }, resumption_token: "rt" } });

  it("a stale incoming snapshot that narrows is reconciled against the peer's own authority, restoring a newly granted capability", async () => {
    let granted: Record<string, unknown> = {};
    let slow = true;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onCapabilityList: async () => {
          calls++;
          const snapshot = { ...granted }; // captured when it starts
          if (slow && calls === 1) await gate; // the first list is slow
          return { wmp: { version: "0.1" }, capabilities: snapshot, security: { mode: "tls" } };
        },
      },
    });
    const v = vci();
    peer.use(v.profile);
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } }); // captures {}
    await settle();
    t.sent.length = 0;
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, add: { oid4vci: {} } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // grants oid4vci
    await upd;
    granted = { oid4vci: {} }; // and so does this peer's own authority
    release(); // the old list finishes with its stale {}
    await settle(40);
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error).toBeUndefined(); // the grant was not left permanently narrowed
    expect(v.onVCIStart).toHaveBeenCalled();
    void slow;
  });

  it("a stale snapshot that names exactly what is cached triggers no refresh (no ping-pong between peers)", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const v = vci();
    peer.use(v.profile);
    const c = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1", { oid4vci: {} }));
    await c;
    t.sent.length = 0;
    const l1 = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const l2 = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    await settle();
    const [id1, id2] = t.sent.map((m) => (m as { id: string }).id);
    t.receive({ jsonrpc: "2.0", id: id1, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // fresh: applies
    t.receive({ jsonrpc: "2.0", id: id2, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } }); // stale but identical membership
    await Promise.all([l1, l2]);
    await settle(30);
    expect(t.sent.filter((m) => (m as { method?: string }).method === "wmp.capability.list")).toHaveLength(2); // no refresh requested
  });
});

describe("grant refresh state is per lifecycle and per source", () => {
  const mkCreate = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
  const createAnswer = (id: string, sid: string, caps: Record<string, unknown> = {}) => ({ jsonrpc: "2.0" as const, id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: caps, security: { mode: "tls" }, resumption_token: "rt" } });
  const ok = (id: string, caps: Record<string, unknown>) => ({ jsonrpc: "2.0" as const, id, result: { wmp: { version: "0.1" }, capabilities: caps, security: { mode: "tls" } } });
  const outgoingLists = (t: MockTransport) => t.sent.filter((m) => (m as { method?: string }).method === "wmp.capability.list") as { id: string }[];

  /** Makes an outgoing stale answer that narrows the grant, which starts a remote refresh (left unanswered). */
  async function staleNarrowing(t: MockTransport, peer: Peer, sid: string): Promise<void> {
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: sid } });
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: sid }, add: { oid4vci: {} } });
    await settle();
    const ids = t.sent.slice(-2).map((m) => (m as { id: string }).id);
    t.receive(ok(ids[1], { oid4vci: {} })); // the grant is now oid4vci
    t.receive(ok(ids[0], {})); // the older, empty snapshot arrives late: narrows, refresh requested
    await Promise.all([list, upd]);
    await settle();
  }

  it("a refresh left over from an earlier session does not hold the next session's refresh up, and finishing late does not clear it", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const c1 = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent[0] as { id: string }).id, "ses-1"));
    await c1;
    await staleNarrowing(t, peer, "ses-1");
    const r1 = outgoingLists(t).at(-1)!; // the refresh of ses-1, never answered for now
    expect(outgoingLists(t)).toHaveLength(2);

    const c2 = peer.createSession({});
    await settle();
    t.receive(createAnswer((t.sent.at(-1) as { id: string }).id, "ses-2"));
    await c2;
    const before = outgoingLists(t).length;
    await staleNarrowing(t, peer, "ses-2");
    // ses-2 got its own refresh although ses-1's is still in flight
    expect(outgoingLists(t).length).toBe(before + 2); // l, refresh
    const r2 = outgoingLists(t).at(-1)!;
    expect(r2.id).not.toBe(r1.id);

    // the old refresh finishes late: it must not clear ses-2's marker, so a further stale answer queues behind r2
    t.receive({ jsonrpc: "2.0", id: r1.id, error: { code: -32601, message: "no" } });
    await settle();
    const beforeStale = outgoingLists(t).length;
    const l = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-2" } });
    const u = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-2" }, add: { other: {} } });
    await settle();
    const ids = t.sent.slice(-2).map((m) => (m as { id: string }).id);
    t.receive(ok(ids[1], { oid4vci: {}, other: {} }));
    t.receive(ok(ids[0], { oid4vci: {} })); // stale, differs: wants another refresh
    await Promise.all([l, u]);
    await settle();
    expect(outgoingLists(t).length).toBe(beforeStale + 1); // only the list itself: the refresh waits for r2
    t.receive(ok(r2.id, { oid4vci: {}, other: {} }));
    await settle(30);
    expect(outgoingLists(t).length).toBe(beforeStale + 2); // exactly one queued refresh ran after r2
  });

  it("a refresh requested for the local authority while a remote one is in flight runs against the local authority", async () => {
    let calls = 0;
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const t = new MockTransport();
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async () => ({ wmp: { version: "", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" } }),
        onCapabilityList: async () => {
          calls++;
          if (calls === 1) {
            await gate; // the first list is slow and captures a snapshot that will be stale
            return ok("x", { other: {} }).result;
          }
          return ok("x", { oid4vci: {} }).result;
        },
      },
    });
    t.receive(mkCreate("c"));
    await settle();
    t.receive({ jsonrpc: "2.0", id: "l", method: "wmp.capability.list", params: { wmp: { version: "0.1", session_id: "ses-1" } } }); // slow, captures at the current revision
    await settle();
    t.sent.length = 0;
    await staleNarrowing(t, peer, "ses-1"); // a remote refresh is now in flight
    const remote = outgoingLists(t).at(-1)!;
    release(); // the slow local list finishes with a stale snapshot that differs: a local refresh is queued
    await settle();
    expect(calls).toBe(1); // still queued behind the remote refresh
    const listsBefore = outgoingLists(t).length;
    t.receive(ok(remote.id, {})); // names exactly what is cached: no change, no further remote refresh
    await settle(30);
    expect(calls).toBe(2); // drained against the local authority
    expect(outgoingLists(t).length).toBe(listsBefore); // and not as another request to the remote peer
  });
});

// ---------------------------------------------------------------------------
// Review round 12
// ---------------------------------------------------------------------------

describe("session ordering and resume hygiene (round 12)", () => {
  const ok = (sid: string, extra: Record<string, unknown> = {}) => ({ wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, ...extra });
  const mkClient = async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    peer.use(new OpenID4xProfile({ oid4vci: { supported_grants: [], supported_formats: [] }, onVCIStart: async (p: never) => ({ wmp: (p as { wmp: never }).wmp, flow_id: (p as { flow_id: string }).flow_id, flow_type: "oid4vci" }) as never }));
    const q = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: ok("ses-1", { capabilities: { oid4vci: {} }, resumption_token: "rt1" }) });
    await q;
    t.sent.length = 0;
    return { t, peer };
  };
  const mk = async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: ok("ses-1", { resumption_token: "rt1" }) });
    await p;
    t.sent.length = 0;
    return { t, peer };
  };

  it("a generic wmp.session.resume without explicit params is rejected and sends nothing", async () => {
    const { t, peer } = await mk();
    for (const bad of [undefined, null, [], "x"]) {
      await expect(peer.call("wmp.session.resume", bad as never)).rejects.toMatchObject({ code: -32602 });
    }
    expect(t.sent).toHaveLength(0);
    expect(peer.token).toBe("rt1");
  });

  it("a same-session resume does not make a concurrent createSession stale", async () => {
    const { t, peer } = await mk();
    const create = peer.createSession({}); // issued first
    await settle();
    const createId = (t.sent.at(-1) as { id: string }).id;
    const resume = peer.resumeSession();
    await settle();
    const resumeId = (t.sent.at(-1) as { id: string }).id;
    t.receive({ jsonrpc: "2.0", id: resumeId, result: ok("ses-1", { resumed: true, missed_messages: 0, resumption_token: "rt2" }) });
    await resume.catch(() => undefined);
    t.receive({ jsonrpc: "2.0", id: createId, result: ok("ses-2", { resumption_token: "rtc" }) });
    await expect(create).resolves.toBeDefined();
    expect(peer.session).toBe("ses-2");
  });

  it("overlapping incoming creates: the later request wins even when it finishes first", async () => {
    const t = new MockTransport();
    const gates: Array<() => void> = [];
    const peer = new Peer(t, {
      handler: {
        onSessionCreate: async (p: never) => {
          const n = gates.length;
          await new Promise<void>((r) => gates.push(r));
          return ok(`ses-${n}`) as never;
        },
      },
    });
    void peer;
    t.receive({ jsonrpc: "2.0", id: "a", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    t.receive({ jsonrpc: "2.0", id: "b", method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" } } });
    await settle();
    gates[1]!(); // the later request finishes first
    await settle();
    gates[0]!();
    await settle();
    const byId = (id: string) => t.sent.find((m) => (m as { id?: string }).id === id) as Response;
    expect(byId("b").error).toBeUndefined();
    expect(byId("a").error?.code).toBe(-31000);
    expect(peer.session).toBe("ses-1");
  });

  it("a gap withdraws the grant; a resume without a snapshot leaves it withdrawn and asks for one", async () => {
    const { t } = await mkClient();
    t.emitEvent("gap");
    await settle();
    const resume = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    t.receive({ jsonrpc: "2.0", id: resume.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 1, security: { mode: "tls" } } });
    await settle(30);
    expect(t.sent.some((m) => (m as { method?: string }).method === "wmp.capability.list")).toBe(true);
    t.sent.length = 0;
    t.receive({ jsonrpc: "2.0", id: "f", method: "wmp.flow.start", params: { wmp: { version: "0.1", session_id: "ses-1" }, flow_type: "oid4vci", flow_id: "flow-1", params: {} } });
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
  });

  it("two coalesced gaps: a resume without a snapshot still triggers the capability refresh", async () => {
    const { t } = await mkClient();
    t.emitEvent("gap");
    t.emitEvent("gap"); // coalesced: bumps the revision again
    await settle();
    const resume = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    t.receive({ jsonrpc: "2.0", id: resume.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 1, security: { mode: "tls" } } });
    await settle(30);
    expect(t.sent.some((m) => (m as { method?: string }).method === "wmp.capability.list")).toBe(true);
  });

  it("a gap withdraws the grant at once, even while another resume holds the recovery chain", async () => {
    const { t, peer } = await mkClient();
    const pending = peer.resumeSession(); // unanswered: the recovery of the gap queues behind it
    await settle();
    t.emitEvent("gap");
    t.sent.length = 0;
    t.receive({ jsonrpc: "2.0", id: "f", method: "wmp.flow.start", params: { wmp: { version: "0.1", session_id: "ses-1" }, flow_type: "oid4vci", flow_id: "flow-1", params: {} } });
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    void pending.catch(() => undefined);
  });

  it("an incoming create that arrived first cannot win because its authorization was slow", async () => {
    const t = new MockTransport();
    const gates: Array<() => void> = [];
    const peer = new Peer(t, {
      authorize: async (method, params) => {
        if (method === "wmp.session.create" && (params as { tag?: string }).tag === "slow") await new Promise<void>((r) => gates.push(r));
        return true;
      },
      handler: { onSessionCreate: async (p: never) => ok((p as { tag: string }).tag === "slow" ? "ses-slow" : "ses-fast") as never },
    });
    const c = (id: string, tag: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.session.create", params: { wmp: { version: "0.1" }, security: { mode: "tls" }, tag } });
    t.receive(c("a", "slow"));
    t.receive(c("b", "fast"));
    await settle();
    gates[0]!();
    await settle();
    expect(peer.session).toBe("ses-fast");
    const a = t.sent.find((m) => (m as { id?: string }).id === "a") as Response;
    expect(a.error?.code).toBe(-31000);
  });

  it("the supported_versions in a refusal is a copy", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    void peer;
    const p = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "9.9", session_id: "x" }, capabilities: {}, security: { mode: "tls" } } });
    const err = (await p.then(() => undefined, (e) => e)) as WMPError;
    const data = err.data as { supported_versions: string[] };
    data.supported_versions.push("0.99");
    const p2 = peer.createSession({});
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.99", session_id: "x" }, capabilities: {}, security: { mode: "tls" } } });
    await expect(p2).rejects.toMatchObject({ code: -31013 });
  });
});
