import { describe, it, expect, afterEach, vi } from "vitest";
import { HttpSseTransport } from "../src/transport.js";
import { Peer } from "../src/peer.js";
import { ErrorCode, Method } from "../src/types.js";
import type { Message } from "../src/jsonrpc.js";
import { SseStub } from "./support/sse-stub.js";
import { FetchEventSource } from "./support/eventsource.js";

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
    const { t, sid } = await setup(3, { onFlowComplete });
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

  it("keeps an existing query and a fragment, encodes values, and adds both cursor names", () => {
    expect(urlFor("/e?x=1#frag", "s 1", "c/1")).toBe("/e?x=1&session_id=s+1&last_event_id=c%2F1&lastEventId=c%2F1#frag");
    expect(urlFor("https://h.example:8443/wmp/events", undefined, "c")).toBe("https://h.example:8443/wmp/events?last_event_id=c&lastEventId=c");
    expect(urlFor("https://h.example/e")).toBe("https://h.example/e");
  });
});
