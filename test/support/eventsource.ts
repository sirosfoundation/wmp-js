/**
 * A small fetch-based EventSource for Node tests. Like a browser's: events carry
 * lastEventId, a non-200 response closes the connection for good (readyState
 * CLOSED, no reconnect) and reports an error; unlike a browser's it reads
 * `headers` from the init object (as the usual polyfills do) and never
 * reconnects by itself, so a test controls reconnection explicitly.
 */

type Listener = (ev: MessageEvent) => void;

export class FetchEventSource {
  static readonly CONNECTING = 0;
  static readonly OPEN = 1;
  static readonly CLOSED = 2;
  /** Every instance created, newest last. */
  static instances: FetchEventSource[] = [];

  readyState = 0;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  onmessage: Listener | null = null;
  private listeners = new Map<string, Listener[]>();
  private abort = new AbortController();
  private lastId = "";

  constructor(readonly url: string, readonly init?: { headers?: Record<string, string> }) {
    FetchEventSource.instances.push(this);
    void this.run();
  }

  addEventListener(type: string, fn: Listener): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }

  close(): void {
    this.readyState = 2;
    this.abort.abort();
  }

  private async run(): Promise<void> {
    try {
      const res = await fetch(this.url, {
        headers: { Accept: "text/event-stream", ...(this.init?.headers ?? {}) },
        signal: this.abort.signal,
      });
      if (res.status !== 200) {
        this.readyState = 2;
        this.onerror?.();
        return;
      }
      this.readyState = 1;
      this.onopen?.();
      const reader = res.body!.getReader();
      const dec = new TextDecoder();
      let buf = "";
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i: number;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          this.dispatch(buf.slice(0, i));
          buf = buf.slice(i + 2);
        }
      }
      if (this.readyState !== 2) {
        this.readyState = 0; // a browser would reconnect here
        this.onerror?.();
      }
    } catch {
      if (this.readyState !== 2) {
        this.readyState = 0;
        this.onerror?.();
      }
    }
  }

  private dispatch(block: string): void {
    let type = "message";
    let data = "";
    let any = false;
    for (const line of block.split("\n")) {
      if (line.startsWith(":")) continue;
      const j = line.indexOf(":");
      const f = j < 0 ? line : line.slice(0, j);
      const v = j < 0 ? "" : line.slice(j + 1).replace(/^ /, "");
      if (f === "id") this.lastId = v;
      else if (f === "event") type = v;
      else if (f === "data") data += (data ? "\n" : "") + v;
      else continue;
      any = true;
    }
    if (!any) return;
    const ev = { data, lastEventId: this.lastId, type } as MessageEvent;
    if (type === "message") this.onmessage?.(ev);
    for (const fn of this.listeners.get(type) ?? []) fn(ev);
  }
}
