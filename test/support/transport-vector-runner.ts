/**
 * Executes a transport-http vector (vectors/README.md) over real HTTP against
 * an SseStub-like server. The server-side controls (emit, advance the
 * simulated clock, drop a connection) are passed in as callbacks, so the same
 * runner can drive any server that offers them.
 */

import { expect } from "vitest";

export interface Controls {
  baseUrl: string;
  emit(sessionId: string, message: unknown): void;
  advance(seconds: number): void;
  drop(sessionId: string): void;
}

type Vars = Map<string, unknown>;

interface Step {
  step: string;
  request?: { method: string; path: string; query?: Record<string, string>; headers?: Record<string, string>; body?: unknown };
  conn?: string;
  expect?: Record<string, unknown>;
  label?: string;
  same_response_as?: string;
  emit?: unknown[];
  deliver?: Record<string, { events: unknown[] }>;
  close?: string;
  idle_seconds?: number;
}

interface SseEvent {
  id?: string;
  event?: string;
  data: string;
}

class StreamConn {
  events: SseEvent[] = [];
  comments: string[] = [];
  taken = 0;
  commentsTaken = 0;
  private buf = "";
  private abort = new AbortController();
  constructor(readonly status: number, private res: Response) {}

  static async open(url: string, headers: Record<string, string>): Promise<StreamConn | { status: number; text: string; contentType: string }> {
    const abort = new AbortController();
    const res = await fetch(url, { headers, signal: abort.signal });
    const ct = res.headers.get("content-type") ?? "";
    if (res.status !== 200 || !ct.includes("text/event-stream")) {
      const text = await res.text();
      return { status: res.status, text, contentType: ct };
    }
    const c = new StreamConn(res.status, res);
    c.abort = abort;
    void c.pump();
    return c;
  }

  private async pump(): Promise<void> {
    const reader = this.res.body!.getReader();
    const dec = new TextDecoder();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) return;
        this.buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = this.buf.indexOf("\n\n")) >= 0) {
          this.block(this.buf.slice(0, i));
          this.buf = this.buf.slice(i + 2);
        }
      }
    } catch {
      /* aborted */
    }
  }

  private block(text: string): void {
    const ev: SseEvent = { data: "" };
    let hasField = false;
    for (const line of text.split("\n")) {
      if (line.startsWith(":")) {
        this.comments.push(line);
        continue;
      }
      const j = line.indexOf(":");
      const f = j < 0 ? line : line.slice(0, j);
      const v = j < 0 ? "" : line.slice(j + 1).replace(/^ /, "");
      hasField = true;
      if (f === "id") ev.id = v;
      else if (f === "event") ev.event = v;
      else if (f === "data") ev.data += (ev.data ? "\n" : "") + v;
    }
    if (hasField) this.events.push(ev);
  }

  /** Wait until `n` unseen events arrived (or time out), settle, take all unseen. */
  async take(n: number): Promise<SseEvent[]> {
    const deadline = Date.now() + 2000;
    while (this.events.length - this.taken < n && Date.now() < deadline) await sleep(5);
    await sleep(40);
    const out = this.events.slice(this.taken);
    this.taken = this.events.length;
    return out;
  }

  close(): void {
    this.abort.abort();
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

function subst(v: unknown, vars: Vars): unknown {
  if (typeof v === "string") {
    return v.replace(/\{\{(\w+)\}\}/g, (_, name: string) => {
      if (!vars.has(name)) throw new Error(`unbound variable ${name}`);
      return String(vars.get(name));
    });
  }
  if (Array.isArray(v)) return v.map((x) => subst(x, vars));
  if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, subst(x, vars)]));
  return v;
}

/** Subset match per vectors/README.md. Binds {"capture": name}. */
export function matches(expected: unknown, actual: unknown, vars: Vars, path = "$"): void {
  if (expected && typeof expected === "object" && !Array.isArray(expected)) {
    const e = expected as Record<string, unknown>;
    if ("capture" in e && Object.keys(e).length === 1) {
      expect(actual, `${path}: capture ${String(e.capture)} needs a value`).not.toBeUndefined();
      vars.set(e.capture as string, actual);
      return;
    }
    if ("any" in e && Object.keys(e).length === 1) return;
    expect(actual && typeof actual === "object" && !Array.isArray(actual), `${path}: expected an object`).toBe(true);
    for (const [k, v] of Object.entries(e)) matches(v, (actual as Record<string, unknown>)[k], vars, `${path}.${k}`);
    return;
  }
  if (Array.isArray(expected)) {
    expect(Array.isArray(actual), `${path}: expected an array`).toBe(true);
    const a = actual as unknown[];
    expect(a.length, `${path}: array length`).toBe(expected.length);
    expected.forEach((x, i) => matches(x, a[i], vars, `${path}[${i}]`));
    return;
  }
  if (typeof expected === "string") {
    const s = String(subst(expected, vars));
    if (s.endsWith("*")) expect(String(actual).startsWith(s.slice(0, -1)), `${path}: ${String(actual)} vs ${s}`).toBe(true);
    else expect(actual, path).toBe(s);
    return;
  }
  expect(actual, path).toEqual(expected);
}

function pointerAbsent(obj: unknown, pointer: string): boolean {
  let cur: unknown = obj;
  for (const seg of pointer.split("/").slice(1)) {
    if (cur && typeof cur === "object" && Object.prototype.hasOwnProperty.call(cur, seg)) cur = (cur as Record<string, unknown>)[seg];
    else return true;
  }
  return false;
}

function checkEvents(expectedEvents: unknown[], actual: SseEvent[], vars: Vars, label: string): void {
  expect(actual.length, `${label}: number of events`).toBe(expectedEvents.length);
  expectedEvents.forEach((raw, i) => {
    const e = raw as { event?: string; id?: unknown; data?: unknown; absent?: string[] };
    const a = actual[i];
    expect(a.id, `${label}[${i}]: every event carries an id`).toBeTruthy();
    expect(/^[\x21-\x7e]+$/.test(a.id!), `${label}[${i}]: id is printable ASCII without spaces`).toBe(true);
    if (e.event !== undefined) expect(a.event, `${label}[${i}].event`).toBe(e.event);
    if (e.id !== undefined) matches(e.id, a.id, vars, `${label}[${i}].id`);
    const data = JSON.parse(a.data) as unknown;
    if (e.data !== undefined) matches(e.data, data, vars, `${label}[${i}].data`);
    for (const p of e.absent ?? []) expect(pointerAbsent(data, p), `${label}[${i}]: ${p} must be absent`).toBe(true);
  });
}

/** Runs the vector's steps; throws (via expect) on the first mismatch. */
export async function runTransportVector(input: unknown, ctl: Controls): Promise<void> {
  const vars: Vars = new Map();
  const conns = new Map<string, StreamConn>();
  const labelled = new Map<string, { status: number; text: string }>();
  const steps = input as Step[];
  try {
    for (const raw of steps) {
      const step = subst(raw, vars) as Step;
      const where = step.step;
      if (step.close) {
        const c = conns.get(step.close);
        expect(c, `${where}: unknown connection ${step.close}`).toBeDefined();
        c!.close();
        // The server side notices the drop; the stub also closes its end.
        const sid = String(vars.get("sid"));
        ctl.drop(sid);
        continue;
      }
      if (step.emit) {
        for (const m of step.emit) ctl.emit(String(vars.get("sid")), m);
      } else if (step.request) {
        const r = step.request;
        const url = new URL(ctl.baseUrl + r.path);
        for (const [k, v] of Object.entries(r.query ?? {})) url.searchParams.set(k, v);
        const headers = { ...(r.headers ?? {}) };
        const ex = (raw.expect ?? {}) as Record<string, unknown>;
        if (step.idle_seconds !== undefined && !step.conn) throw new Error("idle_seconds needs a stream");
        if (step.conn) {
          const opened = await StreamConn.open(url.toString(), headers);
          if (opened instanceof StreamConn) {
            expect(ex.status, `${where}: status`).toBe(opened.status);
            expect(ex.stream, `${where}: stream:false but the response is an event stream`).not.toBe(false);
            conns.set(step.conn, opened);
            if (step.idle_seconds !== undefined) {
              await sleep(20);
              ctl.advance(step.idle_seconds);
              await sleep(40);
              expect(opened.comments.length, `${where}: comments_at_least`).toBeGreaterThanOrEqual(Number(ex.comments_at_least ?? 0));
              if (ex.comments_carry_no_id) expect(opened.events.length, `${where}: a comment must not be an event`).toBe(0);
            }
            const expectedEvents = (ex.events as unknown[] | undefined) ?? [];
            checkEvents(subst(expectedEvents, vars) as unknown[], await opened.take(expectedEvents.length), vars, where);
          } else {
            // Not an event stream. That is only right where the vector says so.
            expect(opened.status, `${where}: status`).toBe(ex.status);
            expect(ex.stream === false || ex.status !== 200, `${where}: expected an event stream, got a ${opened.status} ${opened.contentType} response`).toBe(true);
            if (ex.content_type) expect(opened.contentType, `${where}: content_type`).toContain(String(ex.content_type));
            if (ex.body !== undefined) matches(ex.body, opened.text ? JSON.parse(opened.text) : undefined, vars, `${where}.body`);
            if (step.label) labelled.set(step.label, opened);
            if (step.same_response_as) {
              const prev = labelled.get(step.same_response_as)!;
              expect(opened.status).toBe(prev.status);
              expect(opened.text).toBe(prev.text);
            }
          }
        } else {
          const res = await fetch(url.toString(), {
            method: r.method,
            headers: { "Content-Type": "application/json", ...headers },
            body: r.body === undefined ? undefined : JSON.stringify(r.body),
          });
          const text = await res.text();
          expect(res.status, `${where}: status`).toBe(ex.status);
          if (ex.body !== undefined) matches(ex.body, text ? JSON.parse(text) : undefined, vars, `${where}.body`);
          if (ex.content_type) expect(res.headers.get("content-type") ?? "").toContain(String(ex.content_type));
          if (step.label) labelled.set(step.label, { status: res.status, text });
          if (step.same_response_as) {
            const prev = labelled.get(step.same_response_as)!;
            expect(res.status).toBe(prev.status);
            expect(text).toBe(prev.text);
          }
        }
      }
      for (const [name, d] of Object.entries(step.deliver ?? {})) {
        const c = conns.get(name);
        expect(c, `${where}: deliver names unknown connection ${name}`).toBeDefined();
        checkEvents(subst(d.events, vars) as unknown[], await c!.take(d.events.length), vars, `${where}/${name}`);
      }
    }
  } finally {
    for (const c of conns.values()) c.close();
  }
}
