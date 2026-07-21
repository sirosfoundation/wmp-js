import type { Transport, TransportEvents, TransportEventName } from "../src/transport.js";
import type { Message } from "../src/jsonrpc.js";

/**
 * In-memory, synchronous mock transport for tests.
 */
export class MockTransport implements Transport {
  private listeners = new Map<string, Set<(...args: unknown[]) => void>>();
  sent: Message[] = [];
  closed = false;

  async send(msg: Message): Promise<void> {
    this.sent.push(msg);
  }

  close(): void {
    this.closed = true;
  }

  on<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    let set = this.listeners.get(event);
    if (!set) {
      set = new Set();
      this.listeners.set(event, set);
    }
    set.add(listener as (...args: unknown[]) => void);
  }

  off<K extends TransportEventName>(event: K, listener: TransportEvents[K]): void {
    this.listeners.get(event)?.delete(listener as (...args: unknown[]) => void);
  }

  receive(msg: Message): void {
    this.listeners.get("message")?.forEach((fn) => fn(msg));
  }
}
