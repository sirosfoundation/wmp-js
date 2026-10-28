import { describe, it, expect } from "vitest";
import {
  MemorySessionStore,
  SessionStoreError,
  isSessionExpired,
  sessionOwnedBy,
  tokensEqual,
  type Session,
} from "../src/session-store.js";

const past = () => new Date(Date.now() - 60_000).toISOString();
const future = () => new Date(Date.now() + 60_000).toISOString();

function sess(id: string, extra: Partial<Session> = {}): Session {
  return {
    id,
    participants: ["a"],
    capabilities: {},
    security: { mode: "tls" },
    createdAt: new Date().toISOString(),
    ...extra,
  };
}

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (e) {
    if (e instanceof SessionStoreError) return e.code;
    throw e;
  }
  return "ok";
}

describe("MemorySessionStore", () => {
  it("get hides an expired session but cleanup still counts it", async () => {
    const s = new MemorySessionStore();
    await s.create(sess("live", { expiresAt: future() }));
    await s.create(sess("dead", { expiresAt: past() }));
    expect((await s.get("live"))?.id).toBe("live");
    expect(await s.get("dead")).toBeUndefined();
    expect((await s.listExpired()).map((x) => x.id)).toEqual(["dead"]);
    expect(await s.cleanup()).toBe(1);
    expect(s.size).toBe(1);
  });

  it("treats an unparseable expiry as expired (fail closed) and no expiry as live", async () => {
    const s = new MemorySessionStore();
    await s.create(sess("junk", { expiresAt: "not a date" }));
    await s.create(sess("none"));
    expect(await s.get("junk")).toBeUndefined();
    expect((await s.get("none"))?.id).toBe("none");
  });

  it("compares expiry as instants, not strings (offset form)", () => {
    // 2000-01-01T00:00:00+14:00 is 1999-12-31T10:00:00Z: well in the past, but
    // lexically greater than any "2025-..." Z string.
    expect(isSessionExpired(sess("x", { expiresAt: "2000-01-01T00:00:00+14:00" }))).toBe(true);
  });

  it("list and getByMetadata skip expired sessions", async () => {
    const s = new MemorySessionStore();
    await s.create(sess("a", { metadata: { k: "v" }, expiresAt: future() }));
    await s.create(sess("b", { metadata: { k: "v" }, expiresAt: past() }));
    await s.create(sess("c", { metadata: { k: "other" } }));
    expect((await s.list()).map((x) => x.id).sort()).toEqual(["a", "c"]);
    expect((await s.getByMetadata("k", "v")).map((x) => x.id)).toEqual(["a"]);
  });

  it("owner binding never matches an empty key", () => {
    expect(sessionOwnedBy(sess("a", { owner: "p1" }), "p1")).toBe(true);
    expect(sessionOwnedBy(sess("a", { owner: "p1" }), "p2")).toBe(false);
    expect(sessionOwnedBy(sess("a"), "")).toBe(false);
    expect(sessionOwnedBy(sess("a", { owner: "" }), "")).toBe(false);
  });

  it("createIfAbsent refuses to overwrite; updateIfPresent refuses to resurrect", async () => {
    const s = new MemorySessionStore();
    await s.createIfAbsent(sess("a", { owner: "p1" }));
    expect(await code(s.createIfAbsent(sess("a", { owner: "p2" })))).toBe("session_exists");
    expect((await s.get("a"))?.owner).toBe("p1");
    expect(await code(s.updateIfPresent(sess("zz")))).toBe("no_such_session");
    expect(await code(s.updateIfPresent(sess("a", { owner: "p1" })))).toBe("ok");
  });

  describe("rotateResumptionToken", () => {
    it("rotates once; the old token is dead afterwards", async () => {
      const s = new MemorySessionStore();
      await s.create(sess("a", { resumptionToken: "t1" }));
      const before = await s.get("a");
      const out = await s.rotateResumptionToken("a", "t1", "t2", future());
      expect(out.resumptionToken).toBe("t2");
      expect(out.resumptionTokenExpiresAt).toBeDefined();
      expect(before?.resumptionToken).toBe("t1"); // earlier handout not mutated
      expect(await code(s.rotateResumptionToken("a", "t1", "t3"))).toBe("token_mismatch");
    });

    it("rotating without an expiry clears the previous token expiry", async () => {
      const s = new MemorySessionStore();
      await s.create(sess("a", { resumptionToken: "t1", resumptionTokenExpiresAt: future() }));
      const out = await s.rotateResumptionToken("a", "t1", "t2");
      expect(out.resumptionTokenExpiresAt).toBeUndefined();
    });

    it("rejects empty old token, expired token, bad new token, missing and expired sessions", async () => {
      const s = new MemorySessionStore();
      await s.create(sess("a", { resumptionToken: "t1" }));
      await s.create(sess("tok", { resumptionToken: "t1", resumptionTokenExpiresAt: past() }));
      await s.create(sess("gone", { resumptionToken: "t1", expiresAt: past() }));
      await s.create(sess("unset"));
      expect(await code(s.rotateResumptionToken("a", "", "t2"))).toBe("token_mismatch");
      expect(await code(s.rotateResumptionToken("unset", "", "t2"))).toBe("token_mismatch");
      expect(await code(s.rotateResumptionToken("tok", "t1", "t2"))).toBe("token_expired");
      expect(await code(s.rotateResumptionToken("a", "t1", ""))).toBe("invalid_new_token");
      expect(await code(s.rotateResumptionToken("a", "t1", "t1"))).toBe("invalid_new_token");
      expect(await code(s.rotateResumptionToken("gone", "t1", "t2"))).toBe("no_such_session");
      expect(await code(s.rotateResumptionToken("nope", "t1", "t2"))).toBe("no_such_session");
    });
  });
});

describe("tokensEqual", () => {
  it("is true only for identical strings", () => {
    expect(tokensEqual("abc", "abc")).toBe(true);
    expect(tokensEqual("abc", "abd")).toBe(false);
    expect(tokensEqual("abc", "abcd")).toBe(false);
    expect(tokensEqual("", "")).toBe(true);
    expect(tokensEqual("", "a")).toBe(false);
  });
});
