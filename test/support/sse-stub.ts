/**
 * A Node http server that behaves like a WMP HTTPS binding server as the
 * transport-http vectors describe it (Transport Section 4.3): server-assigned
 * session IDs, principal binding, event IDs, a bounded event buffer with an
 * eviction watermark, Last-Event-ID / last_event_id replay with the header
 * winning, 410 on a gap, redacted retained copies, heartbeat comments on a
 * simulated clock, and the re-send of flow state on wmp.session.resume.
 *
 * It exists because go-wmp's secured server is not released yet; it is the
 * "server side" of the vector runner and of the HttpSseTransport tests.
 */

import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomBytes } from "node:crypto";
import { splitReplaySecrets } from "../../src/completion.js";

interface BufferedEvent {
  seq: number;
  id: string;
  data: string; // retained (redacted) JSON text
}

interface Conn {
  res: ServerResponse;
  idleSeconds: number;
}

interface Sess {
  id: string;
  owner: string;
  token: string;
  seq: number;
  watermark: number; // seq of the newest evicted event, 0 = none
  buffer: BufferedEvent[];
  issued: Map<string, number>; // event id -> seq, for every event ever issued
  conns: Set<Conn>;
  activeProgress: Map<string, string>; // flow_id -> retained latest progress
  terminal: Map<string, string>; // flow_id -> retained terminal notification
}

export interface StubOptions {
  eventBuffer: number;
  principals: Record<string, string>; // name -> Authorization header value
}

const HEARTBEAT_SECONDS = 30;

export class SseStub {
  private server: Server;
  private sessions = new Map<string, Sess>();
  /** JSON-RPC messages the stub received by POST (other than create/resume). */
  received: unknown[] = [];
  /** Every GET of the event stream: cursor sources as sent. */
  gets: { header?: string; query: Record<string, string> }[] = [];
  url = "";

  constructor(private opts: StubOptions) {
    this.server = createServer((req, res) => {
      this.handle(req, res).catch(() => {
        if (!res.headersSent) res.writeHead(500);
        res.end();
      });
    });
  }

  async start(): Promise<void> {
    await new Promise<void>((resolve) => this.server.listen(0, "127.0.0.1", resolve));
    const addr = this.server.address();
    if (typeof addr === "string" || addr === null) throw new Error("no address");
    this.url = `http://127.0.0.1:${addr.port}`;
  }

  async stop(): Promise<void> {
    this.dropAllConnections();
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server.close(() => resolve()));
  }

  // -- test controls -------------------------------------------------------

  sessionIds(): string[] {
    return [...this.sessions.keys()];
  }

  /** Emit a notification to a session: live to open streams, retained redacted. */
  emit(sessionId: string, message: unknown): void {
    const s = this.sessions.get(sessionId);
    if (!s) throw new Error("no such session");
    const live = JSON.stringify(message);
    const split = splitReplaySecrets(live);
    if (!split.ok) throw new Error("message cannot be retained");
    this.push(s, split.replay, live);
    const m = message as { method?: string; params?: { flow_id?: string } };
    const flow = m.params?.flow_id;
    if (flow !== undefined) {
      if (m.method === "wmp.flow.progress") s.activeProgress.set(flow, split.replay);
      else if (m.method === "wmp.flow.complete" || m.method === "wmp.flow.error" || m.method === "wmp.flow.cancel") {
        s.activeProgress.delete(flow);
        s.terminal.set(flow, split.replay);
      }
    }
  }

  /** Advance the simulated clock; idle streams get heartbeat comments. */
  advance(seconds: number): void {
    for (const s of this.sessions.values()) {
      for (const c of s.conns) {
        c.idleSeconds += seconds;
        while (c.idleSeconds >= HEARTBEAT_SECONDS) {
          c.res.write(": keepalive\n\n");
          c.idleSeconds -= HEARTBEAT_SECONDS;
        }
      }
    }
  }

  /** Close every open event stream of a session (a dropped connection). */
  dropConnections(sessionId: string): void {
    const s = this.sessions.get(sessionId);
    if (!s) return;
    for (const c of s.conns) c.res.end();
    s.conns.clear();
  }

  dropAllConnections(): void {
    for (const id of this.sessions.keys()) this.dropConnections(id);
  }

  // -- internals -----------------------------------------------------------

  private push(s: Sess, retained: string, live: string): void {
    s.seq++;
    const id = `ev-${s.seq.toString(36)}-${randomBytes(3).toString("hex")}`;
    s.issued.set(id, s.seq);
    s.buffer.push({ seq: s.seq, id, data: retained });
    while (s.buffer.length > this.opts.eventBuffer) {
      s.watermark = s.buffer.shift()!.seq;
    }
    for (const c of s.conns) {
      c.res.write(frame(id, live));
      c.idleSeconds = 0;
    }
  }

  private principal(req: IncomingMessage): string | undefined {
    const auth = req.headers["authorization"];
    if (typeof auth !== "string") return undefined;
    for (const [name, value] of Object.entries(this.opts.principals)) {
      if (auth === value) return name;
    }
    return undefined;
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", this.url);
    const who = this.principal(req);
    if (who === undefined) {
      res.writeHead(401, { "Content-Type": "application/json" }).end('{"error":"unauthorized"}');
      return;
    }
    if (req.method === "POST" && url.pathname === "/wmp") return this.post(req, res, who);
    if (req.method === "GET" && url.pathname === "/wmp/events") return this.events(req, res, url, who);
    res.writeHead(404).end();
  }

  private async post(req: IncomingMessage, res: ServerResponse, who: string): Promise<void> {
    const body = JSON.parse(await readBody(req)) as {
      id?: string;
      method: string;
      params?: Record<string, unknown> & { wmp?: { session_id?: string }; session_id?: string; resumption_token?: string };
    };
    const reply = (obj: unknown): void => {
      res.writeHead(200, { "Content-Type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", id: body.id, ...(obj as object) }));
    };
    const err = (code: number, message: string): void => reply({ error: { code, message } });
    const headerSid = req.headers["wmp-session-id"];

    if (body.method === "wmp.session.create") {
      if (body.params?.wmp?.session_id !== undefined || headerSid !== undefined) {
        return err(-32602, "Invalid params");
      }
      const sid = `ses-${randomBytes(16).toString("hex")}`;
      const s: Sess = {
        id: sid,
        owner: who,
        token: randomBytes(24).toString("base64url"),
        seq: 0,
        watermark: 0,
        buffer: [],
        issued: new Map(),
        conns: new Set(),
        activeProgress: new Map(),
        terminal: new Map(),
      };
      this.sessions.set(sid, s);
      return reply({
        result: { wmp: { version: "0.1", session_id: sid }, capabilities: {}, security: { mode: "tls" }, resumption_token: s.token },
      });
    }

    const sid = body.params?.session_id ?? body.params?.wmp?.session_id ?? (typeof headerSid === "string" ? headerSid : undefined);
    const s = sid ? this.sessions.get(sid) : undefined;
    if (!s || s.owner !== who) return err(-31000, "Session not found");

    if (body.method === "wmp.session.resume") {
      if (body.params?.resumption_token !== s.token) return err(-31000, "Session not found");
      s.token = randomBytes(24).toString("base64url");
      reply({
        result: { wmp: { version: "0.1", session_id: s.id }, resumed: true, resumption_token: s.token, missed_messages: 0, security: { mode: "tls" } },
      });
      // The state a client needs to continue: latest progress of active flows,
      // then the terminal notification of ended flows, as fresh events.
      for (const text of [...s.activeProgress.values(), ...s.terminal.values()]) this.push(s, text, text);
      return;
    }

    // A flow started under a reused id is a new flow: the earlier flow's retained
    // progress and terminal notification must not be re-sent on resume.
    if (body.method === "wmp.flow.start") {
      const fid = (body.params as { flow_id?: unknown } | undefined)?.flow_id;
      if (typeof fid === "string") {
        s.activeProgress.delete(fid);
        s.terminal.delete(fid);
      }
    }
    this.received.push(body);
    res.writeHead(202).end();
  }

  private events(req: IncomingMessage, res: ServerResponse, url: URL, who: string): void {
    const sid = url.searchParams.get("session_id") ?? "";
    const s = this.sessions.get(sid);
    if (!s || s.owner !== who) {
      res.writeHead(404, { "Content-Type": "application/json" }).end('{"error":"session not found"}');
      return;
    }
    const query = Object.fromEntries(url.searchParams);
    const header = req.headers["last-event-id"];
    this.gets.push({ header: typeof header === "string" ? header : undefined, query });
    const cursor = typeof header === "string" && header !== "" ? header : url.searchParams.get("last_event_id") || undefined;

    let replay: BufferedEvent[] = [];
    if (cursor !== undefined) {
      const seq = s.issued.get(cursor);
      if (seq === undefined || seq < s.watermark) {
        res.writeHead(410, { "Content-Type": "application/json" }).end(JSON.stringify({ jsonrpc: "2.0", error: { code: -31000, message: "Gone" } }));
        return;
      }
      replay = s.buffer.filter((e) => e.seq > seq);
    }
    res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache" });
    res.flushHeaders();
    for (const e of replay) res.write(frame(e.id, e.data));
    const conn: Conn = { res, idleSeconds: 0 };
    s.conns.add(conn);
    res.on("close", () => s.conns.delete(conn));
  }
}

function frame(id: string, data: string): string {
  return `id: ${id}\nevent: wmp\ndata: ${data}\n\n`;
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}
