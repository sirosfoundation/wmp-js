/**
 * WMP Invitation — session bootstrap via out-of-band invitation exchange.
 * See wmp-invitation.md for the specification.
 */

import type { Capabilities } from "./types.js";
import { extractDomain } from "./discovery.js";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Invitation purpose values. */
export const InvitationPurpose = {
  Session: "session",
  OID4VCI: "oid4vci",
  OID4VP: "oid4vp",
  Join: "join",
} as const;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** A self-contained, signed invitation that bootstraps a WMP session. */
export interface Invitation {
  /** Inviter's wallet provider identifier (domain-based, discoverable). */
  provider: string;
  /** Inviter's participant identifier (may be non-discoverable, e.g. did:key). */
  sender: string;
  /** Unique, cryptographically random nonce (at least 128 bits). */
  nonce: string;
  /** Inviter's relay endpoint URL (optional shortcut, skips well-known fetch). */
  relay?: string;
  /** Purpose of the invitation. Default: "session". */
  purpose?: string;
  /** Existing session to join (when purpose is "join"). */
  session_id?: string;
  /** Human-readable label for the inviter (informational only). */
  label?: string;
  /** Pre-advertised capabilities (informational, subject to negotiation). */
  capabilities?: Capabilities;
  /** ISO 8601 expiry timestamp. */
  expires_at: string;
  /** Detached JWS signature over the invitation payload. */
  signature: string;
}

/** Options for creating an invitation. */
export interface CreateInvitationOptions {
  provider: string;
  sender: string;
  /** TTL in seconds. Default: 300 (5 minutes). */
  ttl?: number;
  relay?: string;
  purpose?: string;
  session_id?: string;
  label?: string;
  capabilities?: Capabilities;
}

// ---------------------------------------------------------------------------
// Nonce generation
// ---------------------------------------------------------------------------

/**
 * Generate a cryptographically random nonce with the "inv-" prefix.
 * Uses 128 bits of randomness.
 */
export function generateNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  // base64url encode without padding
  const b64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `inv-${b64}`;
}

// ---------------------------------------------------------------------------
// Invitation creation & parsing
// ---------------------------------------------------------------------------

/**
 * Create an unsigned invitation. The caller must set `signature` after
 * signing the payload with the sender's key.
 */
export function createInvitation(opts: CreateInvitationOptions): Invitation {
  const ttl = opts.ttl ?? 300;
  const expiresAt = new Date(Date.now() + ttl * 1000).toISOString();

  return {
    provider: opts.provider,
    sender: opts.sender,
    nonce: generateNonce(),
    relay: opts.relay,
    purpose: opts.purpose ?? InvitationPurpose.Session,
    session_id: opts.session_id,
    label: opts.label,
    capabilities: opts.capabilities,
    expires_at: expiresAt,
    signature: "", // caller sets after signing
  };
}

/**
 * Get the signing payload for an invitation (all fields except `signature`).
 * The caller should JCS-canonicalize and sign this JSON.
 */
export function invitationSigningPayload(
  inv: Invitation,
): Record<string, unknown> {
  const { signature: _, ...rest } = inv;
  // Remove undefined values
  return JSON.parse(JSON.stringify(rest));
}

/**
 * Serialize an invitation to a `wmp://invite?data=<base64url>` URI.
 */
export function invitationToURI(inv: Invitation): string {
  const json = JSON.stringify(inv);
  const b64 = btoa(json)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `wmp://invite?data=${b64}`;
}

/**
 * Serialize an invitation to an HTTPS fallback URI:
 * `https://<provider-domain>/wmp/invite#<base64url>`.
 */
export function invitationToHTTPSURI(inv: Invitation): string {
  const domain = extractDomain(inv.provider);
  if (!domain) {
    throw new Error(
      `Cannot extract domain from provider "${inv.provider}"`,
    );
  }
  const json = JSON.stringify(inv);
  const b64 = btoa(json)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
  return `https://${domain}/wmp/invite#${b64}`;
}

/**
 * Parse an invitation from a `wmp://invite?data=...` URI or
 * `https://...#...` HTTPS fallback URI.
 * Does NOT verify the signature.
 */
export function parseInvitationURI(uri: string): Invitation {
  let encoded: string;

  if (uri.startsWith("wmp://invite")) {
    const url = new URL(uri);
    const data = url.searchParams.get("data");
    if (!data) {
      const ref = url.searchParams.get("ref");
      if (ref) {
        throw new Error(
          `Invitation uses ref="${ref}": fetch the URL to get the full invitation`,
        );
      }
      throw new Error("Invitation URI missing 'data' parameter");
    }
    encoded = data;
  } else if (uri.includes("/wmp/invite#")) {
    const idx = uri.lastIndexOf("#");
    if (idx < 0 || idx === uri.length - 1) {
      throw new Error("HTTPS invitation URI missing fragment");
    }
    encoded = uri.slice(idx + 1);
  } else {
    throw new Error(`Unrecognised invitation URI scheme: "${uri}"`);
  }

  // base64url decode
  const padded = encoded.replace(/-/g, "+").replace(/_/g, "/");
  const json = atob(padded);
  return JSON.parse(json) as Invitation;
}

/**
 * Parse an invitation from raw JSON.
 * Does NOT verify the signature.
 */
export function parseInvitationJSON(data: string | object): Invitation {
  if (typeof data === "string") {
    return JSON.parse(data) as Invitation;
  }
  return data as Invitation;
}

/**
 * Check whether an invitation has expired.
 */
export function isInvitationExpired(inv: Invitation): boolean {
  return new Date(inv.expires_at).getTime() < Date.now();
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

/**
 * Verify the detached JWS signature of an invitation.
 *
 * The verifier receives the canonical signing payload (as a Uint8Array) and
 * the detached signature string. It must return true iff the signature is
 * valid for the sender's public key.
 *
 * IMPORTANT: parseInvitationURI / parseInvitationJSON do NOT verify the
 * signature. Callers must call verifyInvitation before trusting an invitation.
 */
export type InvitationVerifier = (
  payload: Uint8Array,
  signature: string,
) => boolean | Promise<boolean>;

/**
 * Verify an invitation's signature and expiry.
 *
 * @param inv The parsed invitation.
 * @param verifier Callback that verifies the detached JWS signature.
 * @returns The invitation if valid.
 * @throws Error if the invitation is expired or the signature is invalid.
 */
export async function verifyInvitation(
  inv: Invitation,
  verifier: InvitationVerifier,
): Promise<Invitation> {
  if (isInvitationExpired(inv)) {
    throw new Error("invitation expired");
  }
  if (!inv.signature) {
    throw new Error("invitation missing signature");
  }

  const payload = new TextEncoder().encode(
    JSON.stringify(invitationSigningPayload(inv)),
  );
  const valid = await verifier(payload, inv.signature);
  if (!valid) {
    throw new Error("invitation signature verification failed");
  }
  return inv;
}

// ---------------------------------------------------------------------------
// In-memory invitation store
// ---------------------------------------------------------------------------

/**
 * InvitationStore tracks issued invitation nonces.
 */
export interface InvitationStore {
  /** Store a nonce with its invitation. Rejects if nonce already exists. */
  put(nonce: string, inv: Invitation): void;
  /** Atomically consume a nonce. Returns the invitation or undefined. */
  consume(nonce: string): Invitation | undefined;
  /** Remove expired nonces. Returns the count removed. */
  cleanup(): number;
}

/**
 * Thread-safe (single-threaded JS) in-memory invitation store.
 */
export class MemoryInvitationStore implements InvitationStore {
  private nonces = new Map<string, Invitation>();

  put(nonce: string, inv: Invitation): void {
    if (this.nonces.has(nonce)) {
      throw new Error(`Nonce "${nonce}" already exists`);
    }
    this.nonces.set(nonce, inv);
  }

  consume(nonce: string): Invitation | undefined {
    const inv = this.nonces.get(nonce);
    if (!inv) return undefined;
    if (isInvitationExpired(inv)) {
      this.nonces.delete(nonce);
      return undefined;
    }
    this.nonces.delete(nonce);
    return inv;
  }

  cleanup(): number {
    let count = 0;
    for (const [nonce, inv] of this.nonces) {
      if (isInvitationExpired(inv)) {
        this.nonces.delete(nonce);
        count++;
      }
    }
    return count;
  }
}

/**
 * Validate an invitation_nonce from a wmp.session.create request.
 * Returns the original invitation on success, or throws with an error reason.
 */
export function validateInvitationNonce(
  store: InvitationStore,
  nonce: string | undefined,
): Invitation {
  if (!nonce) {
    throw new Error("missing invitation_nonce");
  }
  const inv = store.consume(nonce);
  if (!inv) {
    throw new Error("invalid_invitation_nonce");
  }
  return inv;
}
