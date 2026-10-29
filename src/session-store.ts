/**
 * SessionStore — server-side session persistence interface.
 * Mirrors go-wmp/pkg/wmp/session.go (v0.11.0) for alignment.
 */

import type { Capabilities, SecurityMode } from "./types.js";

export interface Session {
  id: string;
  participants: string[];
  capabilities: Capabilities;
  security: SecurityMode;
  createdAt: string;
  /** RFC 3339 expiry of the session. Absent means the session does not expire. */
  expiresAt?: string;
  metadata?: Record<string, unknown>;
  /** Current single-use resumption token (go-wmp Session.ResumptionToken). */
  resumptionToken?: string;
  /**
   * Opaque key of the authenticated principal that created the session
   * (go-wmp Session.Owner). Absent or empty means unowned.
   */
  owner?: string;
  /**
   * RFC 3339 bound on the validity of {@link resumptionToken}. Absent means the
   * token does not expire on its own (it still dies with the session).
   */
  resumptionTokenExpiresAt?: string;
}

/** Sentinel error codes, mirroring the go-wmp sentinel errors in session.go. */
export type SessionStoreErrorCode =
  | "no_such_session"
  | "token_mismatch"
  | "invalid_new_token"
  | "session_exists"
  | "token_expired";

/** Error raised by the optional store extensions. */
export class SessionStoreError extends Error {
  constructor(
    readonly code: SessionStoreErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "SessionStoreError";
  }
}

/**
 * True when `now` is past `deadline`. Only an absent (undefined) deadline never
 * expires; a deadline that does not parse, an empty string included, counts as
 * expired (fail closed).
 */
function pastDeadline(deadline: string | undefined, now: number): boolean {
  if (deadline === undefined) return false;
  const t = Date.parse(deadline);
  return Number.isNaN(t) || now > t;
}

/** Mirrors go-wmp Session.IsExpired. */
export function isSessionExpired(session: Session, now: number = Date.now()): boolean {
  return pastDeadline(session.expiresAt, now);
}

/**
 * Mirrors go-wmp Session.OwnedBy: an empty key never matches, so an
 * unauthenticated caller cannot claim an unowned session.
 */
export function sessionOwnedBy(session: Session, ownerKey: string): boolean {
  return ownerKey !== "" && (session.owner ?? "") === ownerKey;
}

/**
 * Compares two tokens without an early exit on the first differing character
 * (mirrors go-wmp TokensEqual). Differing lengths are unequal.
 */
export function tokensEqual(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const n = Math.max(a.length, b.length);
  for (let i = 0; i < n; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

export interface SessionStore {
  create(session: Session): Promise<void>;
  /** Returns the session, or undefined when it is absent or expired. */
  get(id: string): Promise<Session | undefined>;
  update(session: Session): Promise<void>;
  delete(id: string): Promise<void>;
  /** Returns all non-expired sessions where metadata[key] === value. */
  getByMetadata(key: string, value: string): Promise<Session[]>;
  /** Returns all active (non-expired) sessions. */
  list(): Promise<Session[]>;
  /** Removes all expired sessions and returns the count removed. */
  cleanup(): Promise<number>;
}

/**
 * Optional extension (go-wmp TokenRotator): atomic compare-and-swap rotation of
 * a single-use resumption token. Rejects with a {@link SessionStoreError}:
 * no_such_session (absent or expired), token_mismatch (old token empty or not
 * current), token_expired (current but past resumptionTokenExpiresAt),
 * invalid_new_token (empty or equal to the old token).
 */
export interface TokenRotator {
  rotateResumptionToken(
    id: string,
    oldToken: string,
    newToken: string,
    expiresAt?: string,
  ): Promise<Session>;
}

/** Optional extension (go-wmp SessionCreator): create without overwriting. */
export interface SessionCreator {
  /** Rejects with session_exists when the id is already stored. */
  createIfAbsent(session: Session): Promise<void>;
}

/** Optional extension (go-wmp SessionUpdater): update without resurrecting. */
export interface SessionUpdater {
  /** Rejects with no_such_session when the id is not stored. */
  updateIfPresent(session: Session): Promise<void>;
}

/** Optional extension (go-wmp ExpiredSessionLister). */
export interface ExpiredSessionLister {
  listExpired(): Promise<Session[]>;
}

/**
 * In-memory SessionStore — suitable for development and testing.
 */
export class MemorySessionStore
  implements SessionStore, TokenRotator, SessionCreator, SessionUpdater, ExpiredSessionLister
{
  private sessions = new Map<string, Session>();

  async create(session: Session): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async get(id: string): Promise<Session | undefined> {
    const s = this.sessions.get(id);
    if (!s || isSessionExpired(s)) return undefined;
    return s;
  }

  async update(session: Session): Promise<void> {
    this.sessions.set(session.id, { ...session });
  }

  async delete(id: string): Promise<void> {
    this.sessions.delete(id);
  }

  async getByMetadata(key: string, value: string): Promise<Session[]> {
    const now = Date.now();
    const out: Session[] = [];
    for (const s of this.sessions.values()) {
      if (s.metadata && s.metadata[key] === value && !isSessionExpired(s, now)) out.push(s);
    }
    return out;
  }

  async list(): Promise<Session[]> {
    const now = Date.now();
    return [...this.sessions.values()].filter((s) => !isSessionExpired(s, now));
  }

  async cleanup(): Promise<number> {
    const now = Date.now();
    let count = 0;
    for (const [id, session] of this.sessions) {
      if (isSessionExpired(session, now)) {
        this.sessions.delete(id);
        count++;
      }
    }
    return count;
  }

  async listExpired(): Promise<Session[]> {
    const now = Date.now();
    return [...this.sessions.values()].filter((s) => isSessionExpired(s, now));
  }

  async createIfAbsent(session: Session): Promise<void> {
    if (this.sessions.has(session.id)) {
      throw new SessionStoreError("session_exists", "wmp: session already exists");
    }
    this.sessions.set(session.id, { ...session });
  }

  async updateIfPresent(session: Session): Promise<void> {
    if (!this.sessions.has(session.id)) {
      throw new SessionStoreError("no_such_session", "wmp: no such session");
    }
    this.sessions.set(session.id, { ...session });
  }

  /**
   * The stored session is replaced by an updated copy, so objects handed out
   * earlier by {@link get} are never mutated.
   */
  async rotateResumptionToken(
    id: string,
    oldToken: string,
    newToken: string,
    expiresAt?: string,
  ): Promise<Session> {
    if (newToken === "" || tokensEqual(newToken, oldToken)) {
      throw new SessionStoreError("invalid_new_token", "wmp: invalid replacement resumption token");
    }
    const sess = this.sessions.get(id);
    if (!sess || isSessionExpired(sess)) {
      throw new SessionStoreError("no_such_session", "wmp: no such session");
    }
    if (oldToken === "" || !tokensEqual(sess.resumptionToken ?? "", oldToken)) {
      throw new SessionStoreError("token_mismatch", "wmp: resumption token mismatch");
    }
    if (pastDeadline(sess.resumptionTokenExpiresAt, Date.now())) {
      throw new SessionStoreError("token_expired", "wmp: resumption token expired");
    }
    const updated: Session = { ...sess, resumptionToken: newToken };
    if (expiresAt === undefined) delete updated.resumptionTokenExpiresAt;
    else updated.resumptionTokenExpiresAt = expiresAt;
    this.sessions.set(id, updated);
    return updated;
  }

  get size(): number {
    return this.sessions.size;
  }
}
