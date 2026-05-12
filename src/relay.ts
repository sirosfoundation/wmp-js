/**
 * WMP Relay profile — rendezvous relay with offline message queue.
 *
 * Per wmp-transport.md §6.2–6.5, a relay:
 * - Accepts registrations via wmp.relay.register
 * - Routes incoming traffic to registered participants
 * - Queues messages when a participant is offline
 */

import type { Metadata } from "./types.js";
import { Method, ErrorCode } from "./types.js";
import type { MethodHandler } from "./profile.js";
import { WMPError } from "./jsonrpc.js";
import type { RelayRegisterParams, RelayRegisterResult } from "./types.js";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface RelayConfig {
  /** Max messages queued per participant. Default: 1000. */
  maxQueueSize?: number;

  /** Message TTL in milliseconds. Default: 24 hours. */
  messageTTL?: number;

  /** Registration TTL in milliseconds. Default: 1 hour. */
  registrationTTL?: number;

  /** Called when a message is forwarded to a registered peer. */
  onForward?: (participant: string, msg: unknown) => Promise<void>;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface QueuedMessage {
  data: unknown;
  queuedAt: number;
  expiresAt: number;
}

interface Registration {
  participant: string;
  registeredAt: number;
  expiresAt: number;
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

const DEFAULT_MAX_QUEUE = 1000;
const DEFAULT_MSG_TTL = 24 * 60 * 60 * 1000; // 24h
const DEFAULT_REG_TTL = 60 * 60 * 1000; // 1h

export class Relay implements MethodHandler {
  private maxQueueSize: number;
  private messageTTL: number;
  private registrationTTL: number;
  private onForward?: (participant: string, msg: unknown) => Promise<void>;

  private registrations = new Map<string, Registration>();
  private queues = new Map<string, QueuedMessage[]>();

  constructor(config?: RelayConfig) {
    this.maxQueueSize = config?.maxQueueSize ?? DEFAULT_MAX_QUEUE;
    this.messageTTL = config?.messageTTL ?? DEFAULT_MSG_TTL;
    this.registrationTTL = config?.registrationTTL ?? DEFAULT_REG_TTL;
    this.onForward = config?.onForward;
  }

  // --- MethodHandler ---

  methods(): string[] {
    return [Method.RelayRegister];
  }

  async handleMethod(method: string, params: unknown): Promise<unknown> {
    if (method !== Method.RelayRegister) {
      throw new WMPError(ErrorCode.MethodNotFound, `Unknown relay method: ${method}`);
    }

    const p = params as RelayRegisterParams;
    if (!p.wmp?.sender) {
      throw new WMPError(ErrorCode.InvalidParams, "sender required");
    }

    const now = Date.now();
    this.registrations.set(p.wmp.sender, {
      participant: p.wmp.sender,
      registeredAt: now,
      expiresAt: now + this.registrationTTL,
    });

    const result: RelayRegisterResult = {
      wmp: { version: "0.1" },
      registered: true,
      ttl: Math.floor(this.registrationTTL / 1000),
    };
    return result;
  }

  // --- Relay operations ---

  /** Check if a participant is currently registered. */
  isRegistered(participant: string): boolean {
    const reg = this.registrations.get(participant);
    return reg !== undefined && Date.now() < reg.expiresAt;
  }

  /** Enqueue a message for offline delivery. */
  enqueue(participant: string, data: unknown): void {
    let queue = this.queues.get(participant) ?? [];

    // Purge expired
    const now = Date.now();
    queue = queue.filter((m) => now < m.expiresAt);

    if (queue.length >= this.maxQueueSize) {
      throw new WMPError(ErrorCode.QueueFull, "Message queue is full");
    }

    queue.push({
      data,
      queuedAt: now,
      expiresAt: now + this.messageTTL,
    });
    this.queues.set(participant, queue);
  }

  /** Drain all queued messages for a participant. */
  drain(participant: string): QueuedMessage[] {
    const queue = this.queues.get(participant);
    if (!queue || queue.length === 0) return [];

    const now = Date.now();
    const result = queue.filter((m) => now < m.expiresAt);
    this.queues.delete(participant);
    return result;
  }

  /** Get the number of queued messages. */
  queueLength(participant: string): number {
    return this.queues.get(participant)?.length ?? 0;
  }

  /** Remove a participant's registration. */
  unregister(participant: string): void {
    this.registrations.delete(participant);
  }

  /** Purge expired registrations and messages. */
  purgeExpired(): void {
    const now = Date.now();

    for (const [id, reg] of this.registrations) {
      if (now >= reg.expiresAt) {
        this.registrations.delete(id);
      }
    }

    for (const [id, queue] of this.queues) {
      const filtered = queue.filter((m) => now < m.expiresAt);
      if (filtered.length === 0) {
        this.queues.delete(id);
      } else {
        this.queues.set(id, filtered);
      }
    }
  }
}
