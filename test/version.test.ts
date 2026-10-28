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
