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
    // the open stream moved to the new session on its own, without A's cursor
    expect(made).toHaveLength(2);
    expect(made[1].url).toBe("http://x/events?session_id=ses-B");
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

describe("stable flow generations and recovery epochs (round 6)", () => {
  const settle6 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const startF = (id: string, flow: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: flow, params: {} } });
  const complete = (flow: string) => ({ jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } } });
  const onStart = async (p: { wmp: never; flow_id: string; flow_type: string }) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type });

  it("a repeat while the first cancellation is pending shares it even after the flow completed, and the outcome is recorded", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await gate;
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    new Peer(t, { handler: { onFlowStart: onStart as never, onFlowCancel, onFlowComplete: vi.fn() } });
    t.receive(startF("s", "f"));
    await settle6();
    t.receive(cancel("f", "c1")); // pending
    await settle6();
    t.receive(complete("f")); // the flow ends while the cancellation is pending
    await settle6();
    t.receive(cancel("f", "c2")); // a replay: shares the pending one
    await settle6();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    release();
    await settle6();
    t.sent.length = 0;
    t.receive(cancel("f", "c3")); // after it succeeded: acknowledged without the handler
    await settle6();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("cancelled");
  });

  it("a cancellation with no record cannot relabel a replacement flow that also finished", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      if (onFlowCancel.mock.calls.length === 1) await gate;
      return { wmp: p.wmp, flow_id: p.flow_id, status: "from-handler" };
    });
    new Peer(t, { handler: { onFlowStart: onStart as never, onFlowCancel, onFlowComplete: vi.fn() } });
    t.receive(cancel("x", "c1")); // no flow x yet: pending
    await settle6();
    t.receive(startF("s", "x")); // a flow starts under the id
    await settle6();
    t.receive(complete("x")); // and finishes before the handler returns
    await settle6();
    release();
    await settle6();
    t.sent.length = 0;
    t.receive(cancel("x", "c2")); // first cancel of the finished flow: must reach the handler
    await settle6();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("from-handler");
  });

  const created = async (peer: Peer, t: MockTransport, sid: string, token: string) => {
    const p = peer.createSession({});
    await settle6();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: token } });
    await p;
  };
  const resumeReqs = (t: MockTransport) => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { session_id: string; resumption_token: string } }[];

  it("a late recovery result for session A does not overwrite session B (success or failure)", async () => {
    for (const outcome of ["success", "failure"] as const) {
      const t = new MockTransport();
      const lost: Error[] = [];
      const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
      await created(peer, t, "ses-A", "rtA");
      t.emitEvent("gap");
      await settle6();
      const resumeA = resumeReqs(t)[0];
      expect(resumeA.params.session_id).toBe("ses-A");
      await created(peer, t, "ses-B", "rtB"); // B replaces A while A's recovery is in flight
      t.receive(
        outcome === "success"
          ? { jsonrpc: "2.0", id: resumeA.id, result: { wmp: { version: "0.1", session_id: "ses-A" }, resumed: true, missed_messages: 0, resumption_token: "rtA2", security: { mode: "tls" } } }
          : { jsonrpc: "2.0", id: resumeA.id, error: { code: -31001, message: "expired" } },
      );
      await settle6(30);
      expect(peer.session, outcome).toBe("ses-B");
      expect(peer.token, outcome).toBe("rtB");
      expect(lost, outcome).toHaveLength(0);
    }
  });

  it("queued recovery for an old session is discarded, never run against the new one", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    await created(peer, t, "ses-A", "rtA");
    const explicit = peer.resumeSession(); // on the wire
    await settle6();
    t.emitEvent("gap"); // queued behind it
    await settle6();
    await created(peer, t, "ses-B", "rtB");
    t.receive({ jsonrpc: "2.0", id: resumeReqs(t)[0].id, result: { wmp: { version: "0.1", session_id: "ses-A" }, resumed: true, missed_messages: 0, resumption_token: "rtA2", security: { mode: "tls" } } });
    await explicit.catch(() => {});
    await settle6(30);
    expect(resumeReqs(t)).toHaveLength(1); // no resume was sent for B
    expect(lost).toHaveLength(0);
    expect(peer.session).toBe("ses-B");
  });

  it("recovery queued before close() is discarded", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    await created(peer, t, "ses-A", "rtA");
    const explicit = peer.resumeSession();
    await settle6();
    t.emitEvent("gap");
    await settle6();
    peer.close();
    await explicit.catch(() => {});
    await settle6(30);
    expect(resumeReqs(t)).toHaveLength(1);
    expect(lost).toHaveLength(0);
  });
});

describe("rolled-back generations and per-session recovery queue (round 7)", () => {
  const settle7 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const startF = (id: string, flow: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: flow, params: {} } });
  const complete = (flow: string) => ({ jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } } });

  it("a rejected reuse of the id leaves the generation a pending cancellation belongs to", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let accept = true;
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await gate;
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => {
          if (!accept) throw new WMPError(ErrorCode.InvalidParams, "no");
          return { wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type };
        },
        onFlowCancel,
        onFlowComplete: vi.fn(),
      },
    });
    t.receive(startF("s1", "f"));
    await settle7();
    t.receive(cancel("f", "c1")); // pending
    await settle7();
    t.receive(complete("f")); // the flow ends
    await settle7();
    accept = false;
    t.receive(startF("s2", "f")); // an attempt to reuse the id is rejected
    await settle7();
    release(); // the original cancellation finishes
    await settle7();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    t.sent.length = 0;
    t.receive(cancel("f", "c2")); // a replay: the outcome was recorded
    await settle7();
    expect(onFlowCancel).toHaveBeenCalledTimes(1);
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("cancelled");
  });

  it("rejected starts with fresh ids leave no generation entries behind", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: async () => { throw new WMPError(ErrorCode.InvalidParams, "no"); } } });
    for (let i = 0; i < 50; i++) t.receive(startF(`s${i}`, `fresh-${i}`));
    await settle7(30);
    expect((peer as unknown as { flowGen: Map<string, number> }).flowGen.size).toBe(0);
  });

  const created = async (peer: Peer, t: MockTransport, sid: string, token: string) => {
    const p = peer.createSession({});
    await settle7();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: token } });
    await p;
  };
  const resumeReqs = (t: MockTransport) => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { session_id: string; resumption_token: string } }[];

  it("a start that fails leaves no generation behind for work captured during it", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let fail = true;
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await gate;
      return { wmp: p.wmp, flow_id: p.flow_id, status: "from-handler" };
    });
    new Peer(t, {
      handler: {
        onFlowStart: async (p) => {
          if (fail) {
            await new Promise((r) => setTimeout(r, 30)); // pending, then fails
            throw new WMPError(ErrorCode.InvalidParams, "no");
          }
          return { wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type };
        },
        onFlowCancel,
        onFlowComplete: vi.fn(),
      },
    });
    t.receive(startF("s1", "f")); // pending (tentative generation allocated)
    await settle7();
    t.receive(cancel("f", "c1")); // captures the tentative generation
    await settle7(60); // the start fails and is rolled back
    fail = false;
    t.receive(startF("s2", "f")); // a real flow under the id
    await settle7();
    t.receive(complete("f"));
    await settle7();
    release(); // the old cancellation finishes now: it must not relabel the new flow
    await settle7();
    t.sent.length = 0;
    t.receive(cancel("f", "c2")); // first cancel of the new, ended flow: reaches the handler
    await settle7();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
  });

  it("a stale session's queued recovery does not swallow the next session's gap", async () => {
    const t = new MockTransport();
    const lost: Error[] = [];
    const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
    await created(peer, t, "ses-A", "rtA");
    const explicit = peer.resumeSession(); // A's resume is on the wire
    await settle7();
    t.emitEvent("gap"); // A's recovery queued behind it
    await settle7();
    t.emitEvent("gap"); // a second A gap: this one waits its turn behind the first recovery task
    await settle7();
    await created(peer, t, "ses-B", "rtB"); // B replaces A
    t.emitEvent("gap"); // B's gap while A's stale recovery is still queued
    await settle7();
    t.receive({ jsonrpc: "2.0", id: resumeReqs(t)[0].id, result: { wmp: { version: "0.1", session_id: "ses-A" }, resumed: true, missed_messages: 0, resumption_token: "rtA2", security: { mode: "tls" } } });
    await explicit.catch(() => {});
    await settle7(40);
    const reqs = resumeReqs(t);
    expect(reqs).toHaveLength(2); // A's explicit one, then B's recovery (A's queued one was discarded)
    expect(reqs[1].params).toMatchObject({ session_id: "ses-B", resumption_token: "rtB" });
    t.receive({ jsonrpc: "2.0", id: reqs[1].id, result: { wmp: { version: "0.1", session_id: "ses-B" }, resumed: true, missed_messages: 0, resumption_token: "rtB2", security: { mode: "tls" } } });
    await settle7(30);
    expect(lost).toHaveLength(0);
    expect(peer.token).toBe("rtB2");
  });
});

describe("stub: a reused flow id starts clean (round 9)", () => {
  const settleS = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  it("recovery before the replacement finishes does not re-send the old flow's terminal notification", async () => {
    const onFlowComplete = vi.fn();
    const { t, sid, peer } = await setup(3, { onFlowComplete });
    peer.startFlow("sign", "f", {}).catch(() => {});
    await settleS(40);
    stub.emit(sid, { jsonrpc: "2.0", method: "wmp.flow.complete", params: { wmp: { version: "0.1", session_id: sid }, flow_id: "f", result: { credentials: [] } } });
    await settleS(40);
    expect(onFlowComplete).toHaveBeenCalledTimes(1);
    peer.startFlow("sign", "f", {}).catch(() => {}); // a new flow under the same id
    await settleS(40);
    stub.dropConnections(sid);
    for (let i = 0; i < 5; i++) stub.emit(sid, progress(sid, "other", `s${i}`));
    t.reconnectSSE(); // gap -> resume re-sends retained flow state
    await settleS(250);
    expect(onFlowComplete).toHaveBeenCalledTimes(1); // the old terminal was not replayed onto the replacement
  });
});

describe("housekeeping (round 9)", () => {
  const settle9 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const gens = (peer: Peer) => (peer as unknown as { flowGen: Map<string, number> }).flowGen;
  const startF = (id: string, flow: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: flow, params: {} } });
  const onStart = async (p: { wmp: never; flow_id: string; flow_type: string }) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type });

  it("flow generations are reclaimed when a flow is finished locally or its cancellation succeeded", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, { handler: { onFlowStart: onStart as never, onFlowCancel: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }) } });
    for (let i = 0; i < 20; i++) {
      t.receive(startF(`s${i}`, `f${i}`));
      await Promise.resolve();
      await Promise.resolve();
      await peer.flowComplete(`f${i}`, {});
    }
    t.receive(startF("sc", "c1"));
    await settle9();
    peer.flowCancel("c1").catch(() => {});
    await settle9();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1" }, flow_id: "c1", status: "cancelled" } });
    await settle9();
    expect(gens(peer).size).toBe(0);
  });

  it("a pending cancellation keeps its flow's generation until it is done", async () => {
    const t = new MockTransport();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const peer = new Peer(t, { handler: { onFlowStart: onStart as never, onFlowCancel: async (p) => { await gate; return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" }; }, onFlowComplete: vi.fn() } });
    t.receive(startF("s", "f"));
    await settle9();
    t.receive({ jsonrpc: "2.0", id: "c1", method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: "f" } });
    await settle9();
    await peer.flowComplete("f", {}); // finished locally while the cancellation is pending
    expect(gens(peer).size).toBe(1);
    release();
    await settle9();
    expect(gens(peer).size).toBe(0);
  });

  const created = async (peer: Peer, t: MockTransport, sid: string, token: string) => {
    const p = peer.createSession({});
    await settle9();
    t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: token } });
    await p;
  };

  it("an explicit resume queued for session A does not run against session B", async () => {
    const t = new MockTransport();
    const peer = new Peer(t, {});
    await created(peer, t, "ses-A", "rtA");
    const first = peer.resumeSession({ lastReceivedId: "evA1" }); // on the wire
    await settle9();
    const second = peer.resumeSession({ lastReceivedId: "evA2" }); // queued behind it
    second.catch(() => {});
    await settle9();
    await created(peer, t, "ses-B", "rtB"); // B replaces A
    const resumes = () => t.sent.filter((m) => (m as { method?: string }).method === "wmp.session.resume") as { id: string; params: { session_id: string; resumption_token: string; last_received_id?: string } }[];
    t.receive({ jsonrpc: "2.0", id: resumes()[0].id, result: { wmp: { version: "0.1", session_id: "ses-A" }, resumed: true, missed_messages: 0, resumption_token: "rtA2", security: { mode: "tls" } } });
    await first.catch(() => {});
    await expect(second).rejects.toBeDefined();
    await settle9(30);
    expect(resumes()).toHaveLength(1); // nothing was sent for B with A's lastReceivedId
    expect(peer.session).toBe("ses-B");
  });

  it("a 410 probe for session A that finishes after session B was bound does not produce a gap", async () => {
    const instances: { onerror: (() => void) | null; onopen: (() => void) | null; readyState: number }[] = [];
    class Closed {
      readyState = 2;
      onopen: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage = null;
      constructor() {
        instances.push(this);
        // streams opened after the first one (a recovery) open at once
        if (instances.length > 1) queueMicrotask(() => this.onopen?.());
      }
      addEventListener() {}
      close() {}
    }
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    const fetchFn = vi.fn(async () => {
      await gate;
      return { status: 410 } as Response;
    });
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Closed as unknown as typeof EventSource, fetch: fetchFn as never, lastEventId: "cursor-A" });
    const gaps = vi.fn();
    const errors = vi.fn();
    t.on("gap", gaps);
    t.on("error", errors);
    t.setSessionId("ses-A");
    t.connectSSE();
    instances[0].onerror?.(); // the stream for A failed: the probe starts
    await settle9();
    t.setSessionId("ses-B"); // B is bound while the probe is pending
    release();
    await settle9(30);
    expect(gaps).not.toHaveBeenCalled();
    expect(errors).not.toHaveBeenCalled();
    expect(t.lastEventId).toBeUndefined(); // and B's replay state was reset by the switch, not by A's 410
  });

  it("clearSession forgets the binding, the cursor and the seen ids and closes the stream", () => {
    const closed: number[] = [];
    class Fake {
      readyState = 1;
      onopen = null;
      onerror = null;
      onmessage = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string) {
        this.l.forEach((fn) => fn({ data: JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } }), lastEventId: id } as MessageEvent));
      }
      close() {
        closed.push(1);
      }
    }
    const made: Fake[] = [];
    const Ctor = class extends Fake {
      constructor() {
        super();
        made.push(this);
      }
    };
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor as unknown as typeof EventSource });
    t.setSessionId("ses-A");
    t.connectSSE();
    made[0].fire("1");
    expect(t.lastEventId).toBe("1");
    t.clearSession();
    expect(t.lastEventId).toBeUndefined();
    expect(closed).toHaveLength(1);
    t.connectSSE();
    made[1].fire("1"); // the same id in a new session is a new event (no stale seen ids)
    expect(t.lastEventId).toBe("1");
  });
});

describe("stale streams and session ends (round 10)", () => {
  const settle10 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const msg = JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } });
  function fake() {
    const made: { url: string; closed: boolean; fire(id: string, data?: string): void }[] = [];
    class Fake {
      readyState = 1;
      closed = false;
      onopen: (() => void) | null = null;
      onerror: (() => void) | null = null;
      onmessage = null;
      private l: ((ev: MessageEvent) => void)[] = [];
      constructor(public url: string) {
        made.push(this);
      }
      addEventListener(_t: string, fn: (ev: MessageEvent) => void) {
        this.l.push(fn);
      }
      fire(id: string, data = msg) {
        this.l.forEach((fn) => fn({ data, lastEventId: id } as MessageEvent));
      }
      close() {
        this.closed = true;
      }
    }
    return { made, Ctor: Fake as unknown as typeof EventSource };
  }

  it("events of session A's stream arriving after session B was bound are ignored and do not touch B's replay state", () => {
    const { made, Ctor } = fake();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor });
    const got: Message[] = [];
    t.on("message", (m) => got.push(m));
    t.setSessionId("ses-A");
    t.connectSSE();
    t.setSessionId("ses-B"); // A's stream is closed and B's opened
    expect(made[0].closed).toBe(true);
    made[0].fire("a1"); // a late event from A's stream
    expect(got).toHaveLength(0);
    expect(t.lastEventId).toBeUndefined();
    made[1].fire("b1");
    expect(got).toHaveLength(1);
    expect(t.lastEventId).toBe("b1");
  });

  it("clearSession closes the stream and the next bound session reopens it, clean", () => {
    const { made, Ctor } = fake();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor });
    t.setSessionId("ses-A");
    t.connectSSE();
    made[0].fire("1");
    t.clearSession();
    expect(made[0].closed).toBe(true);
    expect(made).toHaveLength(1);
    t.setSessionId("ses-B"); // the next session: the stream comes back by itself
    expect(made).toHaveLength(2);
    expect(made[1].url).toBe("http://x/events?session_id=ses-B");
    expect(t.lastEventId).toBeUndefined();
  });

  it("a transport that never streamed does not start streaming when a session is bound", () => {
    const { made, Ctor } = fake();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor });
    t.setSessionId("ses-A");
    t.setSessionId("ses-B");
    t.clearSession();
    t.setSessionId("ses-C");
    expect(made).toHaveLength(0);
  });

  it("a session.close handled synchronously while its event is delivered does not leave its id as the next session's cursor", () => {
    const { made, Ctor } = fake();
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Ctor });
    t.setSessionId("ses-A");
    t.on("message", () => t.clearSession()); // the application ends the session in response to the message
    t.connectSSE();
    made[0].fire("close-evt");
    expect(t.lastEventId).toBeUndefined();
    t.setSessionId("ses-B");
    expect(made[1].url).toBe("http://x/events?session_id=ses-B"); // no inherited cursor
  });

  it("the Peer drops the transport's binding before it reports a lost session, so the fallback create works", async () => {
    for (const mode of ["no-token", "resume-failed"] as const) {
      const t = new MockTransport() as MockTransport & { clearSession?: () => void; setSessionId?: (id: string) => void };
      let bound: string | undefined;
      t.setSessionId = (id) => (bound = id);
      t.clearSession = () => (bound = undefined);
      const boundWhenLost: (string | undefined)[] = [];
      const peer = new Peer(t, { onSessionLost: () => boundWhenLost.push(bound) });
      const p = peer.createSession({});
      await settle10();
      t.receive({ jsonrpc: "2.0", id: (t.sent[0] as { id: string }).id, result: { wmp: { version: "0.1", session_id: "ses-1" }, capabilities: {}, security: { mode: "tls" }, ...(mode === "no-token" ? {} : { resumption_token: "rt" }) } });
      await p;
      expect(bound).toBe("ses-1");
      t.emitEvent("gap");
      await settle10();
      if (mode === "resume-failed") {
        t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, error: { code: -31001, message: "expired" } });
        await settle10(30);
      }
      expect(boundWhenLost, mode).toEqual([undefined]); // already cleared when the application hears of it
    }
  });
});

describe("overlapping cancellations of one flow id (round 10)", () => {
  const settle10 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const cancel = (flow: string, id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: flow } });
  const startF = (id: string, flow: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: flow, params: {} } });
  const complete = (flow: string) => ({ jsonrpc: "2.0" as const, method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: flow, result: { credentials: [] } } });

  it("an older pending cancellation keeps the generation entry while a replacement's own cancellation comes and goes", async () => {
    const t = new MockTransport();
    let releaseOld!: () => void;
    const gateOld = new Promise<void>((r) => (releaseOld = r));
    let call = 0;
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      const mine = ++call;
      if (mine === 1) {
        await gateOld; // the old one, still running
        return { wmp: p.wmp, flow_id: p.flow_id, status: "old" };
      }
      if (mine === 2) throw new WMPError(ErrorCode.FlowError, "replacement cancel fails");
      return { wmp: p.wmp, flow_id: p.flow_id, status: "later" };
    });
    new Peer(t, { handler: { onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowCancel, onFlowComplete: vi.fn() } });
    t.receive(cancel("f", "c1")); // no flow yet: gen 0, pending
    await settle10();
    t.receive(startF("s", "f")); // a flow starts under the id
    await settle10();
    t.receive(cancel("f", "c2")); // the replacement's cancellation overwrites the map entry and fails
    await settle10();
    t.receive(complete("f")); // the replacement ends: its generation would be reclaimed
    await settle10();
    releaseOld(); // the old cancellation finishes now; it must not mark the replacement cancelled
    await settle10();
    t.sent.length = 0;
    t.receive(cancel("f", "c3")); // a legitimate first cancel of the ended flow
    await settle10();
    expect(onFlowCancel).toHaveBeenCalledTimes(3); // reached the handler
    expect((t.sent[0] as { result: { status: string } }).result.status).toBe("later");
  });
});

describe("first binding, create requests, cancellation bookkeeping across resets (round 11)", () => {
  const settle11 = (ms = 10) => new Promise((r) => setTimeout(r, ms));
  const msg = JSON.stringify({ jsonrpc: "2.0", method: "wmp.flow.progress", params: { wmp: { version: "0.1" }, flow_id: "f", step: "1" } });

  it("a stream opened before the first session binding is reopened for it (keeping a seeded cursor), so its events are delivered", () => {
    const made: { url: string; closed: boolean; fire(id: string): void }[] = [];
    class Fake {
      readyState = 1;
      closed = false;
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
      fire(id: string) {
        this.l.forEach((fn) => fn({ data: msg, lastEventId: id } as MessageEvent));
      }
      close() {
        this.closed = true;
      }
    }
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { EventSource: Fake as unknown as typeof EventSource, lastEventId: "seed" });
    const got: Message[] = [];
    t.on("message", (m) => got.push(m));
    t.connectSSE(); // before any session is bound
    t.setSessionId("ses-1"); // the first binding
    expect(made).toHaveLength(2);
    expect(made[0].closed).toBe(true);
    expect(made[1].url).toBe("http://x/events?session_id=ses-1&last_event_id=seed&lastEventId=seed"); // seeded cursor kept
    made[1].fire("e1");
    expect(got).toHaveLength(1); // delivered: the stream knows its session
  });

  it("a session.create POST carries no Wmp-Session-Id even while a session is bound; other requests do", async () => {
    const calls: { headers: Record<string, string>; body: string }[] = [];
    const fetchFn = vi.fn(async (_url: string, init: { headers: Record<string, string>; body: string }) => {
      calls.push({ headers: init.headers, body: init.body });
      return new Response("", { status: 202 });
    });
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { fetch: fetchFn as never });
    t.setSessionId("ses-A");
    await t.send({ jsonrpc: "2.0", id: "1", method: "wmp.session.create", params: { wmp: { version: "0.1" } } });
    await t.send({ jsonrpc: "2.0", id: "2", method: "wmp.flow.start", params: { wmp: { version: "0.1" } } });
    expect(calls[0].headers["Wmp-Session-Id"]).toBeUndefined();
    expect(calls[1].headers["Wmp-Session-Id"]).toBe("ses-A");
    expect(t.lastEventId).toBeUndefined();
    // the binding survived the create (it may fail), so the next request still carries it
    await t.send({ jsonrpc: "2.0", id: "3", method: "wmp.message.deliver", params: { wmp: { version: "0.1" } } });
    expect(calls[2].headers["Wmp-Session-Id"]).toBe("ses-A");
  });

  it("e2e: a second create through the generic call API on the same peer is accepted by the server", async () => {
    const { t, peer, sid } = await setup(200);
    t.connectSSE();
    const second = await peer.call<{ wmp: { session_id: string } }>("wmp.session.create", { wmp: { version: "0.1" }, security: { mode: "tls" } });
    expect(second.wmp.session_id).not.toBe(sid);
    expect(second.wmp.session_id).toMatch(/^ses-/);
  });

  it("a cancellation of an old session finishing late does not touch the new session's bookkeeping", async () => {
    const t = new MockTransport();
    const gates: (() => void)[] = [];
    const onFlowCancel = vi.fn(async (p: { wmp: never; flow_id: string }) => {
      await new Promise<void>((r) => gates.push(r));
      return { wmp: p.wmp, flow_id: p.flow_id, status: "cancelled" };
    });
    const peer = new Peer(t, { handler: { onFlowCancel, onFlowStart: async (p) => ({ wmp: p.wmp, flow_id: p.flow_id, flow_type: p.flow_type }), onFlowComplete: vi.fn() } });
    const created = async (sid: string) => {
      const p = peer.createSession({});
      await settle11();
      t.receive({ jsonrpc: "2.0", id: (t.sent.at(-1) as { id: string }).id, result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: "rt" } });
      await p;
    };
    const cancel = (id: string) => ({ jsonrpc: "2.0" as const, id, method: "wmp.flow.cancel", params: { wmp: { version: "0.1" }, flow_id: "x" } });
    await created("ses-A");
    t.receive(cancel("c1")); // A's cancellation, pending
    await settle11();
    await created("ses-B"); // reset
    t.receive({ jsonrpc: "2.0", id: "s", method: "wmp.flow.start", params: { wmp: { version: "0.1" }, flow_type: "x", flow_id: "x", params: {} } }); // x exists in B
    await settle11();
    t.receive(cancel("c2")); // B's cancellation of the same id, pending (captures x's generation)
    await settle11();
    t.receive({ jsonrpc: "2.0", method: "wmp.flow.complete", params: { wmp: { version: "0.1" }, flow_id: "x", result: { credentials: [] } } }); // x ends: its generation is kept only for the pending cancellation
    await settle11();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    gates[0](); // A's handler finishes: it must not decrement B's count or reclaim B's generation
    await settle11();
    t.receive(cancel("c3")); // a replay in B while B's handler is still running: shared
    await settle11();
    expect(onFlowCancel).toHaveBeenCalledTimes(2);
    gates[1]();
    await settle11();
  });
});

describe("resume requests are routed by the session they ask for (round 12)", () => {
  it("the Wmp-Session-Id of a session.resume names the requested session, the binding is untouched", async () => {
    const calls: Record<string, string>[] = [];
    const fetchFn = vi.fn(async (_url: string, init: { headers: Record<string, string> }) => {
      calls.push(init.headers);
      return new Response("", { status: 202 });
    });
    const t = new HttpSseTransport("http://x/wmp", "http://x/events", { fetch: fetchFn as never });
    t.setSessionId("ses-A");
    await t.send({ jsonrpc: "2.0", id: "1", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, session_id: "ses-B", resumption_token: "x" } });
    expect(calls[0]["Wmp-Session-Id"]).toBe("ses-B");
    await t.send({ jsonrpc: "2.0", id: "2", method: "wmp.flow.start", params: { wmp: { version: "0.1" } } });
    expect(calls[1]["Wmp-Session-Id"]).toBe("ses-A"); // the binding did not move
    await t.send({ jsonrpc: "2.0", id: "3", method: "wmp.session.resume", params: { wmp: { version: "0.1" }, resumption_token: "x" } }); // names none: the bound one
    expect(calls[2]["Wmp-Session-Id"]).toBe("ses-A");
  });
});
