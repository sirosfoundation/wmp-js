/**
 * SessionStore — server-side session persistence interface.
 * Mirrors go-wmp/pkg/wmp/session.go for alignment.
 */

import type { Metadata, Capabilities, SecurityMode } from "./types.js";

export interface Session {
  id: string;
  participants: string[];
  capabilities: Capabilities;
  security: SecurityMode;
  createdAt: string;
  expiresAt?: string;
  metadata?: Record<string, unknown>;
}

export interface SessionStore {
  create(session: Session): Promise<void>;
  get(id: string): Promise<Session | undefined>;
  update(session: Session): Promise<void>;
  delete(id: string): Promise<void>;
  cleanup(): Promise<number>;
}

/**
 * In-memory SessionStore — suitable for development and testing.
 */
export class MemorySessionStore implements SessionStore {
  private sessions = new Map<string, Session>();

  async create(session: Session): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async get(id: string): Promise<Session | undefined> {
    return this.sessions.get(id);
  }

  async update(session: Session): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  async cleanup(): Promise<number> {
    const now = new Date().toISOString();
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (session.expiresAt && session.expiresAt < now) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  get size(): number {
    return this.sessions.size;
  }
}
