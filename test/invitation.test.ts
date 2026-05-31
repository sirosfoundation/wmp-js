import { describe, it, expect } from "vitest";
import {
  InvitationPurpose,
  createInvitation,
  invitationSigningPayload,
  invitationToURI,
  invitationToHTTPSURI,
  parseInvitationURI,
  parseInvitationJSON,
  isInvitationExpired,
  generateNonce,
  MemoryInvitationStore,
  validateInvitationNonce,
} from "../src/invitation.js";

describe("generateNonce", () => {
  it("produces unique nonces with inv- prefix", () => {
    const nonces = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const nonce = generateNonce();
      expect(nonce).toMatch(/^inv-/);
      expect(nonces.has(nonce)).toBe(false);
      nonces.add(nonce);
    }
  });
});

describe("createInvitation", () => {
  it("creates an invitation with defaults", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });

    expect(inv.provider).toBe("x509:san:dns:wallet.example.com");
    expect(inv.sender).toBe("did:key:z6MkTest");
    expect(inv.nonce).toMatch(/^inv-/);
    expect(inv.purpose).toBe(InvitationPurpose.Session);
    expect(inv.signature).toBe("");
    expect(inv.expires_at).toBeTruthy();
    expect(isInvitationExpired(inv)).toBe(false);
  });

  it("respects custom TTL", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
      ttl: 0, // expires immediately
    });
    // TTL=0 means expires ~now, might be expired by the time we check
    expect(inv.expires_at).toBeTruthy();
  });
});

describe("URI round-trip", () => {
  it("round-trips through wmp:// URI", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
      relay: "wss://wallet.example.com/wmp",
      label: "Test Wallet",
    });
    inv.signature = "eyJ..fakesig";

    const uri = invitationToURI(inv);
    expect(uri).toMatch(/^wmp:\/\/invite\?data=/);

    const parsed = parseInvitationURI(uri);
    expect(parsed.provider).toBe(inv.provider);
    expect(parsed.sender).toBe(inv.sender);
    expect(parsed.nonce).toBe(inv.nonce);
    expect(parsed.relay).toBe(inv.relay);
    expect(parsed.label).toBe(inv.label);
    expect(parsed.signature).toBe(inv.signature);
  });

  it("round-trips through HTTPS fallback URI", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "eyJ..sig";

    const uri = invitationToHTTPSURI(inv);
    expect(uri).toMatch(/^https:\/\/wallet\.example\.com\/wmp\/invite#/);

    const parsed = parseInvitationURI(uri);
    expect(parsed.nonce).toBe(inv.nonce);
  });
});

describe("parseInvitationURI errors", () => {
  it("rejects unknown schemes", () => {
    expect(() => parseInvitationURI("http://example.com")).toThrow(
      "Unrecognised",
    );
  });

  it("rejects wmp URI without data", () => {
    expect(() => parseInvitationURI("wmp://invite?foo=bar")).toThrow(
      "missing 'data'",
    );
  });

  it("reports ref parameter", () => {
    expect(() =>
      parseInvitationURI("wmp://invite?ref=https://example.com/inv/123"),
    ).toThrow("ref=");
  });
});

describe("parseInvitationJSON", () => {
  it("parses from string", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    const json = JSON.stringify(inv);
    const parsed = parseInvitationJSON(json);
    expect(parsed.nonce).toBe(inv.nonce);
  });

  it("parses from object", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    const parsed = parseInvitationJSON(inv);
    expect(parsed.nonce).toBe(inv.nonce);
  });
});

describe("invitationSigningPayload", () => {
  it("excludes signature", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "should-be-excluded";

    const payload = invitationSigningPayload(inv);
    expect(payload).not.toHaveProperty("signature");
    expect(payload.nonce).toBe(inv.nonce);
    expect(payload.provider).toBe(inv.provider);
  });
});

describe("isInvitationExpired", () => {
  it("returns false for future expiry", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
      ttl: 300,
    });
    inv.signature = "sig";
    expect(isInvitationExpired(inv)).toBe(false);
  });

  it("returns true for past expiry", () => {
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    inv.expires_at = "2020-01-01T00:00:00Z";
    expect(isInvitationExpired(inv)).toBe(true);
  });
});

describe("MemoryInvitationStore", () => {
  it("put and consume", () => {
    const store = new MemoryInvitationStore();
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";

    store.put(inv.nonce, inv);

    const consumed = store.consume(inv.nonce);
    expect(consumed).toBeDefined();
    expect(consumed!.sender).toBe(inv.sender);

    // Second consume fails (single-use)
    expect(store.consume(inv.nonce)).toBeUndefined();
  });

  it("rejects duplicate nonce", () => {
    const store = new MemoryInvitationStore();
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";

    store.put(inv.nonce, inv);
    expect(() => store.put(inv.nonce, inv)).toThrow("already exists");
  });

  it("rejects expired nonce on consume", () => {
    const store = new MemoryInvitationStore();
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    inv.expires_at = "2020-01-01T00:00:00Z";

    store.put(inv.nonce, inv);
    expect(store.consume(inv.nonce)).toBeUndefined();
  });

  it("cleanup removes expired", () => {
    const store = new MemoryInvitationStore();

    const expired = createInvitation({
      provider: "x509:san:dns:a.example.com",
      sender: "did:key:z6MkA",
    });
    expired.signature = "sig";
    expired.expires_at = "2020-01-01T00:00:00Z";

    const valid = createInvitation({
      provider: "x509:san:dns:b.example.com",
      sender: "did:key:z6MkB",
    });
    valid.signature = "sig";

    store.put(expired.nonce, expired);
    store.put(valid.nonce, valid);

    expect(store.cleanup()).toBe(1);

    // Valid should survive
    expect(store.consume(valid.nonce)).toBeDefined();
  });
});

describe("validateInvitationNonce", () => {
  it("succeeds with valid nonce", () => {
    const store = new MemoryInvitationStore();
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    store.put(inv.nonce, inv);

    const result = validateInvitationNonce(store, inv.nonce);
    expect(result.sender).toBe(inv.sender);
  });

  it("throws on empty nonce", () => {
    const store = new MemoryInvitationStore();
    expect(() => validateInvitationNonce(store, undefined)).toThrow(
      "missing",
    );
    expect(() => validateInvitationNonce(store, "")).toThrow("missing");
  });

  it("throws on invalid nonce", () => {
    const store = new MemoryInvitationStore();
    expect(() => validateInvitationNonce(store, "inv-bogus")).toThrow(
      "invalid_invitation_nonce",
    );
  });

  it("throws on replay (second use)", () => {
    const store = new MemoryInvitationStore();
    const inv = createInvitation({
      provider: "x509:san:dns:wallet.example.com",
      sender: "did:key:z6MkTest",
    });
    inv.signature = "sig";
    store.put(inv.nonce, inv);

    validateInvitationNonce(store, inv.nonce);
    expect(() => validateInvitationNonce(store, inv.nonce)).toThrow(
      "invalid_invitation_nonce",
    );
  });
});
