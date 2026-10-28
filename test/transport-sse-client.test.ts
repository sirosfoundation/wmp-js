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

async function setup(eventBuffer: number): Promise<{ t: HttpSseTransport; peer: Peer; got: Message[]; sid: string; lost: Error[] }> {
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
  const peer = new Peer(t, { onSessionLost: (e) => lost.push(e) });
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
