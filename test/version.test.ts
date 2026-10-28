import { describe, it, expect, vi } from "vitest";
import { negotiateVersion, parseVersion, versionRejection, SUPPORTED_VERSIONS } from "../src/version.js";
import { Peer, type Handler } from "../src/peer.js";
import { OpenID4xProfile } from "../src/openid4x.js";
import { WMPError, type Response } from "../src/jsonrpc.js";
import { ErrorCode } from "../src/types.js";
import { MockTransport } from "./mock-transport.js";

const settle = () => new Promise((r) => setTimeout(r, 10));

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

  it("outgoing capability operations go one at a time, so the last answer is the latest word", async () => {
    const { t, peer, onVCIStart } = await client({ oid4vci: {} });
    const list = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const upd = peer.call("wmp.capability.update", { wmp: { version: "0.1", session_id: "ses-1" }, remove: ["oid4vci"] });
    await settle();
    // the update is not even sent while the list is unanswered
    expect(t.sent.map((m) => (m as { method: string }).method)).toEqual(["wmp.capability.list"]);
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: { oid4vci: {} }, security: { mode: "tls" } } });
    await list;
    await settle();
    expect(t.sent.map((m) => (m as { method: string }).method)).toEqual(["wmp.capability.list", "wmp.capability.update"]);
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } });
    await upd;
    t.sent.length = 0;
    t.receive(startVci("ses-1"));
    await settle();
    expect((t.sent[0] as Response).error?.code).toBe(-31005);
    expect(onVCIStart).not.toHaveBeenCalled();
  });

  it("a failed or timed-out capability call does not block the ones queued behind it", async () => {
    const { t, peer } = await client({});
    const first = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    const second = peer.call("wmp.capability.list", { wmp: { version: "0.1", session_id: "ses-1" } });
    await settle();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, error: { code: -32601, message: "no" } });
    await expect(first).rejects.toBeDefined();
    await settle();
    expect(t.sent).toHaveLength(2); // the second went out after the first failed
    t.receive({ jsonrpc: "2.0", id: (t.sent[1] as { id: string }).id, result: { wmp: { version: "0.1" }, capabilities: {}, security: { mode: "tls" } } });
    await second;
  });

  it("incoming capability handlers run one at a time, so the last one decides", async () => {
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
    expect(onVCIStart).toHaveBeenCalled(); // the grant of the session we still hold is untouched
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

  it("incoming session establishment is serialized: a slow create cannot overwrite a later one", async () => {
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
