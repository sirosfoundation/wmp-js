import { describe, it, expect, afterEach, vi } from "vitest";
import { HttpSseTransport } from "../src/transport.js";
import { Peer } from "../src/peer.js";
import { ErrorCode, Method } from "../src/types.js";
import { WMPError } from "../src/jsonrpc.js";
import type { Message, Response } from "../src/jsonrpc.js";
import { SseStub } from "./support/sse-stub.js";
import { FetchEventSource } from "./support/eventsource.js";
import { MockTransport } from "./mock-transport.js";

const AUTH = "Bearer alice";
const settle = (ms = 80) => new Promise((r) => setTimeout(r, ms));

const progress = (sid: string, flow: string, step: string) => ({
  jsonrpc: "2.0",
  method: "wmp.flow.progress",
  params: { wmp: { version: "0.1", session_id: sid }, flow_id: flow, step },
});

let stub: SseStub;
let transport: HttpSseTransport | undefined;

async function setup(eventBuffer: number, handler: ConstructorParameters<typeof Peer>[1] extends infer O ? (O extends { handler?: infer H } ? H : never) : never = {}): Promise<{ t: HttpSseTransport; peer: Peer; got: Message[]; sid: string; lost: Error[] }> {
  stub = new SseStub({ eventBuffer, principals: { alice: AUTH, bob: "Bearer bob" } });
  await stub.start();
  FetchEventSource.instances = [];
  const t = new HttpSseTransport(`${stub.url}/wmp`, `${stub.url}/wmp/events`, {
    authorization: AUTH,
    EventSource: FetchEventSource as unknown as typeof EventSource,
  });
  transport = t;
  const got: Message[] = [];
  const lost: Error[] = [];
  const peer = new Peer(t, { onSessionLost: (e) => lost.push(e), handler });
  t.on("message", (m) => got.push(m));
  const res = await peer.createSession({ participants: [], capabilities: {} });
  const sid = res.wmp.session_id!;
  t.connectSSE();
  await settle();
  return { t, peer, got, sid, lost };
}

afterEach(async () => {
  transport?.close();
  transport = undefined;
  await stub?.stop();
});

describe("HttpSseTransport event IDs", () => {
  it("records the id of each event and sends it back on reconnect (header and both query names)", async () => {
    const { t, got, sid } = await setup(200);
    expect(t.lastEventId).toBeUndefined();
    stub.emit(sid, progress(sid, "f1", "s1"));
    stub.emit(sid, progress(sid, "f1", "s2"));
    await settle();
    const last = t.lastEventId;
    expect(last).toBeTruthy();
    expect(got.filter((m) => "method" in m && m.method === Method.FlowProgress)).toHaveLength(2);

    stub.dropConnections(sid);
    stub.emit(sid, progress(sid, "f1", "s3"));
    t.reconnectSSE();
    await settle();
    const get = stub.gets.at(-1)!;
    expect(get.header).toBe(last);
    expect(get.query.last_event_id).toBe(last);
    expect(get.query.lastEventId).toBe(last);
    // exactly the one missed event, delivered once
    expect(got.filter((m) => "method" in m && m.method === Method.FlowProgress)).toHaveLength(3);
  });

  it("does not send a cursor before any event arrived", async () => {
    await setup(200);
    const get = stub.gets.at(-1)!;
    expect(get.header).toBeUndefined();
    expect(get.query.last_event_id).toBeUndefined();
  });

  it("seeds the cursor from the lastEventId option", async () => {
    stub = new SseStub({ eventBuffer: 200, principals: { alice: AUTH } });
    await stub.start();
    FetchEventSource.instances = [];
    const sid = (await (await fetch(`${stub.url}/wmp`, { method: "POST", headers: { Authorization: AUTH }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "wmp.session.create", params: { wmp: { version: "0.1" } } }) })).json()).result.wmp.session_id as string;
    stub.emit(sid, progress(sid, "f", "1"));
    const t = new HttpSseTransport(`${stub.url}/wmp`, `${stub.url}/wmp/events`, {
      authorization: AUTH,
      lastEventId: "never-issued",
      EventSource: FetchEventSource as unknown as typeof EventSource,
    });
    transport = t;
    t.setSessionId(sid);
    expect(t.lastEventId).toBe("never-issued");
    t.connectSSE();
    await settle();
    expect(stub.gets[0].query.last_event_id).toBe("never-issued"); // the first request carried the seeded cursor (a 410 follows)
  });

  it("drops an event whose id was already processed and processes new ones", async () => {
    // A fake EventSource that delivers the same event id twice (a replay).
    const sources: { fire(id: string, data: string): void }[] = [];
    class Fake {
      readyState = 1;
      onopen: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage: null = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      constructor() {
        sources.push(this);
      }
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string, data: string) {
        this.l.forEach((fn) => fn({ data, lastEventId: id } as MessageEvent));
      }
      close() {}
    }
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Fake as unknown as typeof EventSource });
    const got: Message[] = [];
    t.on("message", (m) => got.push(m));
    t.connectSSE();
    const n = JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } });
    sources[0].fire("a", n);
    sources[0].fire("b", n);
    sources[0].fire("a", n); // replay of a processed event
    expect(got).toHaveLength(2);
    expect(t.lastEventId).toBe("b");
    // A new connection (reconnect) replaying "b" is deduped too.
    t.reconnectSSE();
    sources[1].fire("b", n);
    sources[1].fire("c", n);
    expect(got).toHaveLength(3);
    expect(t.lastEventId).toBe("c");
  });

  it("an undecodable event still advances the cursor (it is not replayed forever)", async () => {
    const sources: { fire(id: string, data: string): void }[] = [];
    class Fake {
      readyState = 1;
      onopen = null;
      onerror = null;
      onmessage = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      constructor() {
        sources.push(this);
      }
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string, data: string) {
        this.l.forEach((fn) => fn({ data, lastEventId: id } as MessageEvent));
      }
      close() {}
    }
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Fake as unknown as typeof EventSource });
    const errors: Error[] = [];
    t.on("error", (e) => errors.push(e));
    t.connectSSE();
    sources[0].fire("bad", "not json");
    expect(errors).toHaveLength(1);
    expect(t.lastEventId).toBe("bad");
  });

  it("bounds the dedupe window", () => {
    const sources: { fire(id: string, data: string): void }[] = [];
    class Fake {
      readyState = 1;
      onopen = null;
      onerror = null;
      onmessage = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      constructor() {
        sources.push(this);
      }
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string, data: string) {
        this.l.forEach((fn) => fn({ data, lastEventId: id } as MessageEvent));
      }
      close() {}
    }
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Fake as unknown as typeof EventSource, dedupeWindow: 2 });
    let n = 0;
    t.on("message", () => n++);
    t.connectSSE();
    const m = JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } });
    for (const id of ["a", "b", "c"]) sources[0].fire(id, m);
    sources[0].fire("c", m); // still remembered
    sources[0].fire("a", m); // evicted from the window: processed again
    expect(n).toBe(4);
  });
});

describe("410 gap -> resume", () => {
  it("opens a cursorless stream, emits gap, the Peer resumes and the re-sent progress arrives", async () => {
    const { t, peer, got, sid, lost } = await setup(3);
    const atGap: { cursor?: string; open: boolean }[] = [];
    const gaps = vi.fn(() => {
      atGap.push({ cursor: t.lastEventId, open: FetchEventSource.instances.at(-1)!.readyState === 1 });
    });
    t.on("gap", gaps);
    stub.emit(sid, progress(sid, "flow-1", "step-1"));
    await settle();
    const oldCursor = t.lastEventId!;
    const tokenBefore = peer.token;

    stub.dropConnections(sid);
    for (const s of ["step-2", "step-3", "step-4", "step-5", "step-6"]) stub.emit(sid, progress(sid, "flow-1", s));
    t.reconnectSSE(); // cursor = oldCursor, which the 3-event buffer has evicted past
    await settle(250);

    expect(gaps).toHaveBeenCalledTimes(1);
    // At the moment of the gap the cursor is discarded and the new stream is already open.
    expect(atGap[0]).toEqual({ cursor: undefined, open: true });
    expect(t.lastEventId).not.toBe(oldCursor);
    // The cursorless stream was opened, then the resume ran and rotated the token.
    const gets = stub.gets;
    expect(gets.at(-1)!.header).toBeUndefined();
    expect(gets.at(-1)!.query.last_event_id).toBeUndefined();
    expect(peer.token).not.toBe(tokenBefore);
    // The latest progress of the active flow arrived on the new stream.
    const steps = got.filter((m) => "params" in m && (m.params as { step?: string }).step).map((m) => (m as { params: { step: string } }).params.step);
    expect(steps.at(-1)).toBe("step-6");
    expect(lost).toHaveLength(0);
  });

  it("never reconnects with the discarded cursor", async () => {
    const { t, sid } = await setup(3);
    stub.emit(sid, progress(sid, "f", "1"));
    await settle();
    const old = t.lastEventId!;
    stub.dropConnections(sid);
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "f", String(i)));
    t.reconnectSSE();
    await settle(250);
    const withOld = stub.gets.filter((g) => g.header === old || g.query.last_event_id === old);
    // the failed attempt and the probe; nothing after the gap was handled
    const afterGap = stub.gets.slice(stub.gets.findIndex((g) => g.header === undefined && g.query.last_event_id === undefined && stub.gets.indexOf(g) > 0));
    expect(afterGap.some((g) => g.header === old || g.query.last_event_id === old)).toBe(false);
    expect(withOld.length).toBeGreaterThan(0);
  });

  it("reports the session lost when the resume fails", async () => {
    const { t, peer, sid, lost } = await setup(3);
    stub.emit(sid, progress(sid, "f", "1"));
    await settle();
    (peer as unknown as { resumptionToken?: string }).resumptionToken = "wrong-token";
    stub.dropConnections(sid);
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "f", String(i)));
    t.reconnectSSE();
    await settle(250);
    expect(lost).toHaveLength(1);
  });

  it("reports the session lost when there is no resumption token", async () => {
    const { t, peer, sid, lost } = await setup(3);
    stub.emit(sid, progress(sid, "f", "1"));
    await settle();
    (peer as unknown as { resumptionToken?: string }).resumptionToken = undefined;
    stub.dropConnections(sid);
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "f", String(i)));
    t.reconnectSSE();
    await settle(250);
    expect(lost).toHaveLength(1);
  });

  it("does not treat another failure as a gap", async () => {
    const { t, sid } = await setup(200);
    stub.emit(sid, progress(sid, "f", "1"));
    await settle();
    const gaps = vi.fn();
    const errors = vi.fn();
    t.on("gap", gaps);
    t.on("error", errors);
    // Another principal's view of the session is a 404: an error, not a gap.
    t.setSessionId("ses-does-not-exist");
    t.reconnectSSE();
    await settle(150);
    expect(gaps).not.toHaveBeenCalled();
    expect(errors).toHaveBeenCalled();
  });
});

describe("Peer", () => {
  it("passes the last event id as last_received_id on resume", async () => {
    const { t, peer, sid } = await setup(200);
    stub.emit(sid, progress(sid, "f", "1"));
    await settle();
    const spy = vi.spyOn(t, "send");
    await peer.resumeSession();
    const sent = spy.mock.calls[0][0] as { params: { last_received_id?: string } };
    expect(sent.params.last_received_id).toBe(t.lastEventId);
    expect(ErrorCode.SessionNotFound).toBe(-31000);
  });
});

describe("terminal notifications re-sent by a resume are processed once", () => {
  const complete = (sid: string, flow: string) => ({
    jsonrpc: "2.0",
    method: "wmp.flow.complete",
    params: { wmp: { version: "0.1", session_id: sid }, flow_id: flow, result: { credentials: [] } },
  });

  it("an unrelated gap does not repeat the completion callback", async () => {
    const onFlowComplete = vi.fn();
    const { t, sid, peer } = await setup(3, { onFlowComplete });
    void peer.startFlow("sign", "flow-done", {}).catch(() => {}); // a flow this client knows
    await settle();
    stub.emit(sid, complete(sid, "flow-done"));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);

    stub.dropConnections(sid);
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "flow-other", `s${i}`));
    t.reconnectSSE(); // gap -> resume re-sends flow-done's terminal notification with a fresh id
    await settle(250);
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("delivers a terminal notification that was first discovered during recovery", async () => {
    const onFlowComplete = vi.fn();
    const { t, sid } = await setup(3, { onFlowComplete });
    stub.emit(sid, progress(sid, "flow-other", "first")); // gives the client a cursor
    await settle();
    stub.dropConnections(sid);
    stub.emit(sid, complete(sid, "flow-missed")); // while disconnected, then evicted by newer events
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "flow-other", `s${i}`));
    t.reconnectSSE(); // gap -> resume re-sends flow-missed's terminal notification
    await settle(250);
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
  });

  it("a new flow under a reused id is delivered again", async () => {
    const onFlowComplete = vi.fn();
    const { peer, t, sid } = await setup(200, { onFlowComplete });
    void peer.startFlow("sign", "f", {}).catch(() => {});
    await settle();
    stub.emit(sid, complete(sid, "f"));
    await settle();
    stub.emit(sid, complete(sid, "f")); // a repeat, different event id
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    void peer.startFlow("sign", "f", {}).catch(() => {}); // a new flow under the same id
    await settle();
    stub.emit(sid, complete(sid, "f"));
    await settle();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
    expect(t.lastEventId).toBeTruthy();
  });
});

describe("switching sessions resets replay state", () => {
  function fakeEs() {
    const made: { url: string; fire(id: string, data: string): void }[] = [];
    class Fake {
      readyState = 1;
      onopen = null;
      onerror = null;
      onmessage = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      constructor(public url: string) {
        made.push(this);
      }
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string, data: string) {
        this.l.forEach((fn) => fn({ data, lastEventId: id } as MessageEvent));
      }
      close() {}
    }
    return { made, Ctor: Fake as unknown as typeof EventSource };
  }
  const msg = JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } });

  it("drops the cursor and the seen ids when another session is bound", () => {
    const { made, Ctor } = fakeEs();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor });
    const got: Message[] = [];
    t.on("message", (m) => got.push(m));
    t.setSessionId("ses-A");
    t.connectSSE();
    made[0].fire("1", msg);
    expect(t.lastEventId).toBe("1");
    t.setSessionId("ses-B");
    expect(t.lastEventId).toBeUndefined();
    t.reconnectSSE();
    expect(made[1].url).toBe("http://x/events?session_id=ses-B"); // no cursor from A
    made[1].fire("1", msg); // the same id in session B is a new event
    expect(got).toHaveLength(2);
  });

  it("keeps the cursor for the same session and a seeded cursor on first bind", () => {
    const { made, Ctor } = fakeEs();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor, lastEventId: "seed" });
    t.setSessionId("ses-A");
    expect(t.lastEventId).toBe("seed");
    t.connectSSE();
    made[0].fire("2", msg);
    t.setSessionId("ses-A");
    expect(t.lastEventId).toBe("2");
  });
});

describe("event stream URL", () => {
  function urlFor(eventsUrl: string, sid?: string, cursor?: string): string {
    const urls: string[] = [];
    class Fake {
      readyState = 1;
      onopen = null;
      onerror = null;
      onmessage = null;
      constructor(u: string) {
        urls.push(u);
      }
      addEventListener() {}
      close() {}
    }
    const t = new HttpSseTransport("http://x/wmp", eventsUrl, { EventSource: Fake as unknown as typeof EventSource });
    if (sid) t.setSessionId(sid);
    t.connectSSE(cursor);
    return urls[0];
  }

  it("leaves a relative or protocol-relative URL as supplied, adding only the query", () => {
    expect(urlFor("events", "s1")).toBe("events?session_id=s1");
    expect(urlFor("/app/events", "s1")).toBe("/app/events?session_id=s1");
    expect(urlFor("//stream.example/events", "s1")).toBe("//stream.example/events?session_id=s1");
    expect(urlFor("../events", "s1")).toBe("../events?session_id=s1");
  });

  it("drops cursor parameters the supplied URL carried when there is no cursor, keeps the others", () => {
    expect(urlFor("/e?last_event_id=old&lastEventId=old&x=1", "s1")).toBe("/e?x=1&session_id=s1");
    expect(urlFor("/e?last_event_id=old&x=1", "s1", "new")).toBe("/e?x=1&session_id=s1&last_event_id=new&lastEventId=new");
  });

  it("keeps an existing query and a fragment, encodes values, and adds both cursor names", () => {
    expect(urlFor("/e?x=1#frag", "s 1", "c/1")).toBe("/e?x=1&session_id=s+1&last_event_id=c%2F1&lastEventId=c%2F1#frag");
    expect(urlFor("https://h.example:8443/wmp/events", undefined, "c")).toBe("https://h.example:8443/wmp/events?last_event_id=c&lastEventId=c");
    expect(urlFor("https://h.example/e")).toBe("https://h.example/e");
  });
});

describe("terminal bookkeeping (Peer)", () => {
  const settle2 = () => new Promise((r) => setTimeout(r, 10));
  const done = (flow: string, kind: "complete" | "error" = "complete") => ({
    jsonrpc: "2.0" as const,
    method: kind === "complete" ? "wmp.flow.complete" : "wmp.flow.error",
    params: kind === "complete"
      ? { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } }
      : { wmp: { version: "0.1" }, flow_id: flow, code: -31006, message: "x" },
  });
  const cancel = (flow: string, id = "c") => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const startReq = (flow: string) => ({ jsonrpc: "2.0" as const, id: `s-${flow}`, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "sign", flow_id: flow, params: {} } });

  it("a repeated cancellation is acknowledged again without invoking the handler", async () => {
    const t = new MockTransport();
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }));
    new Peer(t, { handler: { onFlowCancel, onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    t.receive(startReq("f1")); // a flow this peer knows
    await settle2();
    t.sent.length = 0;
    t.receive(cancel("f1", "c1"));
    await settle2();
    t.receive(cancel("f1", "c2")); // the re-send after a resume
    await settle2();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    expect(t.sent).toHaveLength(2);
    expect((t.sent[1] as { result: { status: string } }).result.status).toBe("cancelled");
  });

  it("a notification the validator rejected does not make the flow terminal", async () => {
    const t = new MockTransport();
    const onFlowError = vi.fn();
    let reject = true;
    new Peer(t, { handler: { onFlowError }, validator: { validateMethod: () => (reject ? [{ path: "", message: "bad" }] : null) } });
    t.receive(done("f1", "error"));
    await settle2();
    expect(onFlowError).not.toHaveBeenCalled();
    reject = false;
    t.receive(done("f1", "error")); // the valid one is not discarded as a repeat
    await settle2();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a refused completion counts as the flow's terminal (its synthesized error was delivered)", async () => {
    const t = new MockTransport();
    const onFlowError = vi.fn();
    new Peer(t, { handler: { onFlowError, onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    t.receive(startReq("f1"));
    await settle2();
    const bad = { jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "f1", result: { credential_response_encrypted: true, credentials: [{ credential: "x" }] } } };
    t.receive(bad);
    await settle2();
    t.receive(bad);
    await settle2();
    expect(onFlowError).toHaveBeenCalledTimes(1);
  });

  it("a refused attempt to reuse a flow id keeps the old flow's terminal marker", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    let accept = true;
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => {
          if (!accept) throw new WMPError(ErrorCode.InvalidParams, "no");
          return { wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type };
        },
        onFlowComplete,
      },
    });
    t.receive(startReq("f1")); // accepted: a flow this peer knows
    await settle2();
    accept = false;
    t.receive(done("f1"));
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    t.receive(startReq("f1")); // refused
    await settle2();
    t.receive(done("f1")); // the old flow's terminal, re-sent by a resume
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    accept = true;
    t.receive(startReq("f1")); // accepted: a new flow under the id
    await settle2();
    t.receive(done("f1"));
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
  });

  it("an accepted replacement flow's terminal may arrive before its start response", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const peer = new Peer(t, { handler: { onFlowComplete } });
    t.receive(done("f1"));
    await settle2();
    const started = peer.startFlow("sign", "f1", {});
    await settle2();
    t.receive(done("f1")); // the replacement's completion, ahead of the response
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1" }, flow_id: "f1", flow_type: "sign" } });
    await started;
  });

  it("never evicts a marker: replaying thousands of older terminals delivers nothing", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    new Peer(t, { handler: { onFlowComplete, onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    const n = 4200;
    for (let i = 0; i < n; i++) {
      t.receive(startReq(`f${i}`));
      await Promise.resolve();
      await Promise.resolve();
      t.receive(done(`f${i}`));
    }
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(n);
    for (let i = 0; i < n; i++) t.receive(done(`f${i}`)); // a resume re-sends them all
    await settle2();
    expect(onFlowComplete).toHaveBeenCalledTimes(n);
  });
});

describe("cancellation and recovery bookkeeping (round 3)", () => {
  const settle3 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const complete = (flow: string) => ({ jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } } });

  it("a flow that ended by complete still reaches the handler on its first cancel", async () => {
    const t = new MockTransport();
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "already_complete" }));
    new Peer(t, { handler: { onFlowCancel, onFlowComplete: vi.fn(), onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }) } });
    t.receive({ jsonrpc: "2.0" as const, id: "s1", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "f1", params: {} } });
    await settle3();
    t.sent.length = 0;
    t.receive(complete("f1"));
    await settle3();
    t.receive(cancel("f1", "c1"));
    await settle3();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("already_complete");
    t.receive(cancel("f1", "c2")); // a repeat of a cancellation that was processed
    await settle3();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    expect((t.sent[1] as { result: { status: string } }).result.status).toBe("cancelled");
  });

  it("concurrent cancellations of one flow run the handler once and share the outcome; a failure allows a retry", async () => {
    const t = new MockTransport();
    let release!: () => void;
    let gate = new Promise<void>((r) => (release = r));
    let fail = true;
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await gate;
      if (fail) throw new WMPError(ErrorCode.FlowError, "boom");
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    new Peer(t, { handler: { onFlowCancel } });
    t.receive(cancel("f1", "c1"));
    t.receive(cancel("f1", "c2"));
    await settle3();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    release();
    await settle3();
    expect(t.sent.map((m) => (m as Response).error?.code)).toEqual([-31006, -31006]); // both see the failure
    // retry is possible after the failure
    fail = false;
    gate = Promise.resolve();
    t.receive(cancel("f1", "c3"));
    await settle3();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    expect((t.sent[2] as { result: { status: string } }).result.status).toBe("cancelled");
  });

  it("a failed start does not restore a marker over a flow that took the id", async () => {
    const t = new MockTransport();
    const onFlowComplete = vi.fn();
    const peer = new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowComplete } });
    t.receive(complete("f")); // the old flow ended: marker
    await settle3();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    const first = peer.startFlow("sign", "f", {}); // reuse attempt 1, response pending
    first.catch(() => {});
    await settle3();
    t.receive(complete("f")); // the replacement completes before its start response
    await settle3();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
    t.receive({ jsonrpc: "2.0", id: "s2", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "sign", flow_id: "f", params: {} } }); // another flow takes the id
    await settle3();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, error: { code: -31005, message: "x" } }); // attempt 1 fails late
    await settle3();
    t.receive(complete("f")); // the newer flow's completion is delivered, not discarded as a repeat
    await settle3();
    expect(onFlowComplete).toHaveBeenCalledTimes(3);
  });

  it("gaps that arrive while a resume is pending do not send a second resume with the rotated token", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    const created = peer.createSession({});
    await settle3();
    t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" }, resumption_token: "rt1" } });
    await created;
    t.sent.length = 0;
    t.emitEvent("gap");
    await settle3(); // the first resume is on the wire
    t.emitEvent("gap"); // while it is pending: queued behind it
    t.emitEvent("gap"); // coalesced with the queued one
    await settle3();
    const resumes = () => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { resumption_token: string } }[];
    expect(resumes()).toHaveLength(1);
    expect(resumes()[0].params.resumption_token).toBe("rt1");
    t.receive({ jsonrpc: "2.0", id: resumes()[0].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await settle3(30);
    expect(resumes()).toHaveLength(2); // the one follow-up, with the rotated token
    expect(resumes()[1].params.resumption_token).toBe("rt2");
    t.receive({ jsonrpc: "2.0", id: resumes()[1].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt3", security: { mode: "tls" } } });
    await settle3(30);
    expect(lost).toHaveLength(0);
    expect(peer.token).toBe("rt3");
  });
});

describe("cancellation generations (round 4)", () => {
  const settle4 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const complete = (flow: string) => ({ jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } } });
  const startF = (id: string, flow: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: flow, params: {} } });

  it("a cancellation that finishes after its flow ended and another started under the id does not touch the new flow", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const onFlowComplete = vi.fn();
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }),
        onFlowCancel: async (p) => {
          await gate;
          return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
        },
        onFlowComplete,
      },
    });
    t.receive(startF("s1", "f"));
    await settle4();
    t.receive(cancel("f", "c1")); // pending
    await settle4();
    t.receive(complete("f")); // the original flow ends
    await settle4();
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    t.receive(startF("s2", "f")); // a replacement under the same id
    await settle4();
    release(); // the old cancellation finishes now
    await settle4();
    t.receive(complete("f")); // the replacement's completion must be delivered
    await settle4();
    expect(onFlowComplete).toHaveBeenCalledTimes(2);
  });

  it("a replacement flow's cancellation does not share the old generation's pending one", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await gate;
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowCancel, onFlowComplete: vi.fn() } });
    t.receive(startF("s1", "f"));
    await settle4();
    t.receive(cancel("f", "c1"));
    await settle4();
    t.receive(complete("f"));
    await settle4();
    t.receive(startF("s2", "f"));
    await settle4();
    t.receive(cancel("f", "c2")); // the replacement's own cancellation
    await settle4();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    release();
    await settle4();
  });

  it("a handler that throws synchronously leaves a retry possible", async () => {
    const t = new MockTransport();
    let fail = true;
    const onFlowCancel = vi.fn((p: { wmp: never; flow_id: string }) => {
      if (fail) throw new WMPError(ErrorCode.FlowError, "boom"); // synchronous, before any promise exists
      return Promise.resolve({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" });
    });
    new Peer(t, { handler: { onFlowCancel: onFlowCancel as never } });
    t.receive(cancel("f1", "c1"));
    await settle4();
    expect((t.sent[0] as Response).error?.code).toBe(-31006);
    fail = false;
    t.receive(cancel("f1", "c2"));
    await settle4();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    expect((t.sent[1] as { result: { status: string } }).result.status).toBe("cancelled");
  });
});

describe("resumes and cancellations across sessions (round 5)", () => {
  const settle5 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const created = async (peer: Peer, t: MockTransport, sid: string, token = "rt1") => {
    const p = peer.createSession({});
    await settle5();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: token } });
    await p;
  };

  it("a gap while an explicit resume is pending waits for it and presents the rotated token", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    await created(peer, t, "ses-1");
    t.sent.length = 0;
    const explicit = peer.resumeSession();
    await settle5();
    t.emitEvent("gap"); // while the explicit resume is on the wire
    await settle5(30);
    const resumes = () => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { resumption_token: string } }[];
    expect(resumes()).toHaveLength(1);
    t.receive({ jsonrpc: "2.0", id: resumes()[0].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await explicit;
    await settle5(30);
    expect(resumes()).toHaveLength(2);
    expect(resumes()[1].params.resumption_token).toBe("rt2"); // not the consumed rt1
    t.receive({ jsonrpc: "2.0", id: resumes()[1].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt3", security: { mode: "tls" } } });
    await settle5(30);
    expect(lost).toHaveLength(0);
    expect(peer.token).toBe("rt3");
  });

  it("two explicit resumes in a row also use the rotated token", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    await created(peer, t, "ses-1");
    t.sent.length = 0;
    const a = peer.resumeSession();
    const b = peer.resumeSession();
    await settle5();
    const resumes = () => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { resumption_token: string } }[];
    expect(resumes()).toHaveLength(1);
    t.receive({ jsonrpc: "2.0", id: resumes()[0].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt2", security: { mode: "tls" } } });
    await a;
    await settle5();
    expect(resumes()[1].params.resumption_token).toBe("rt2");
    t.receive({ jsonrpc: "2.0", id: resumes()[1].id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: true, missed_messages: 0, resumption_token: "rt3", security: { mode: "tls" } } });
    await b;
  });

  it("an unsuccessful resume result is reported through onSessionLost during recovery", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    await created(peer, t, "ses-1");
    t.sent.length = 0;
    t.emitEvent("gap");
    await settle5();
    const resume = t.sent.find((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string };
    t.receive({ jsonrpc: "2.0", id: resume.id, result: { wmp: { version: "0.1", session_id: "ses-1" }, resumed: false, missed_messages: 0, resumption_token: "rtX", security: { mode: "tls" } } });
    await settle5(30);
    expect(lost).toHaveLength(1);
    expect(peer.token).toBe("rt1"); // nothing was taken from the failed result
  });

  it("a pending cancellation does not follow the flow state into a new session", async () => {
    const t = new MockTransport();
    const gates: (() => void)[] = [];
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await new Promise<void>((r) => gates.push(r));
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    const onFlowComplete = vi.fn();
    const peer = new Peer(t, { handler: { onFlowCancel, onFlowComplete } });
    await created(peer, t, "ses-1");
    t.receive(cancel("x", "c1")); // no record for x: pending
    await settle5();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    await created(peer, t, "ses-2"); // a new session resets the flow state
    t.receive(cancel("x", "c2")); // the same id in the new session must not share the old promise
    await settle5();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    gates[0](); // the old session's handler finishes
    await settle5();
    void peer.startFlow("sign", "x", {}).catch(() => {}); // a flow with that id in the new session
    await settle5();
    t.receive({ jsonrpc: "2.0", method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "x", result: { credentials: [] } } });
    await settle5();
    expect(onFlowComplete).toHaveBeenCalledTimes(1); // not suppressed as already cancelled
    gates[1]();
    await settle5();
  });

  it("an old session's cancellation finishing late does not re-label a flow that ended in the new session", async () => {
    const t = new MockTransport();
    const gates: (() => void)[] = [];
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      if (onFlowCancel.mock.calls.length === 1) await new Promise<void>((r) => gates.push(r)); // only the first, old one is slow
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancel-handler" };
    });
    const peer = new Peer(t, { handler: { onFlowCancel, onFlowComplete: vi.fn() } });
    await created(peer, t, "ses-1");
    t.receive(cancel("x", "c1")); // pending, no record
    await settle5();
    await created(peer, t, "ses-2");
    void peer.startFlow("sign", "x", {}).catch(() => {});
    await settle5();
    t.receive({ jsonrpc: "2.0", method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "x", result: { credentials: [] } } }); // x ended in the new session
    await settle5();
    gates[0](); // the old cancellation finishes now
    await settle5();
    t.sent.length = 0;
    t.receive(cancel("x", "c2")); // first cancel of x in the new session: reaches the handler
    await settle5();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("cancel-handler");
  });
});
