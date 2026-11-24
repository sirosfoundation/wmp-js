import { describe, it, expect } from "vitest";
import {
  discoverEndpoint,
  discoveryBase,
  wellKnownUrl,
} from "../src/discovery.js";

const WK = "/.well-known/wmp-configuration";

/** A fetch that serves the given documents by URL and records what was asked. */
function server(docs: Record<string, unknown>) {
  const asked: string[] = [];
  const fetchFn = (async (url: string) => {
    asked.push(url);
    return url in docs
      ? new Response(JSON.stringify(docs[url]), { status: 200 })
      : new Response("", { status: 404 });
  }) as unknown as typeof globalThis.fetch;
  return { fetchFn, asked };
}

const doc = (ws: string, discovery_base?: string) => ({
  ...(discovery_base === undefined ? {} : { discovery_base }),
  supported_versions: ["0.1"],
  endpoints: { websocket: ws },
  security_modes: ["tls"],
});

describe("discovery base (WMP Core 7.5.1)", () => {
  // The rows of the well-known URL table of the specification.
  it.each([
    ["x509:san:dns:example.com", `https://example.com${WK}`],
    ["https://example.com", `https://example.com${WK}`],
    ["https://example.com/", `https://example.com${WK}`],
    ["https://example.com/tenant1", `https://example.com${WK}/tenant1`],
    [
      "https://example.com:8443/tenants/acme/",
      `https://example.com:8443${WK}/tenants/acme`,
    ],
    [
      "x509:san:uri:https://example.com/tenant1",
      `https://example.com${WK}/tenant1`,
    ],
    ["did:web:example.com", `https://example.com${WK}`],
    ["did:web:example.com%3A8443", `https://example.com:8443${WK}`],
  ])("%s resolves at %s", (identifier, url) => {
    const base = discoveryBase(identifier);
    expect(base).not.toBeNull();
    expect(wellKnownUrl(base!)).toBe(url);
  });

  it.each([
    "did:web:example.com:tenant1",
    "did:key:z6Mkf5rGMoatrSj1f3JWKc",
    "https://example.com/tenant1?x=1",
    "https://example.com/tenant1?",
    "https://example.com/tenant1#frag",
    "https://user@example.com/tenant1",
    "https://example.com/a/../b",
    "https://example.com/a/./b",
    "https://example.com/a/%2e%2e/b",
    "https://example.com\\@evil.example/",
    "x509:san:uri:https://example.com/t?x=1",
    "x509:san:uri:http://example.com/t",
    "x509:san:dns:example.com/path",
    "http://example.com/tenant1",
    "opaque",
  ])("%s has no discovery base", (identifier) => {
    expect(discoveryBase(identifier)).toBeNull();
  });
});

describe("discoverEndpoint", () => {
  const docs = {
    [`https://example.com${WK}`]: doc("wss://root/wmp"),
    [`https://example.com${WK}/tenants/acme`]: doc(
      "wss://acme/wmp",
      "HTTPS://EXAMPLE.com/tenants/acme",
    ),
  };

  it("fetches a tenant's configuration at the inserted URL", async () => {
    for (const id of [
      "https://example.com/tenants/acme",
      "https://example.com/tenants/acme/",
      "x509:san:uri:https://example.com/tenants/acme",
    ]) {
      const { fetchFn, asked } = server(docs);
      const config = await discoverEndpoint(id, fetchFn);
      expect(config.endpoints.websocket).toBe("wss://acme/wmp");
      expect(asked).toEqual([`https://example.com${WK}/tenants/acme`]);
    }
  });

  it("fetches a whole host's configuration at the root", async () => {
    const { fetchFn } = server(docs);
    const config = await discoverEndpoint("x509:san:dns:example.com", fetchFn);
    expect(config.endpoints.websocket).toBe("wss://root/wmp");
  });

  it("does not give a tenant its host's configuration", async () => {
    const { fetchFn, asked } = server(docs);
    await expect(
      discoverEndpoint("https://example.com/tenants/other", fetchFn),
    ).rejects.toThrow(/HTTP 404/);
    expect(asked).toEqual([`https://example.com${WK}/tenants/other`]);
  });

  it("refuses an identifier without a discovery base", async () => {
    const { fetchFn, asked } = server(docs);
    await expect(
      discoverEndpoint("did:web:example.com:tenant1", fetchFn),
    ).rejects.toThrow(/no discovery base/);
    expect(asked).toEqual([]);
  });

  // A catch-all server answers every well-known path with one document.
  it.each([
    ["absent", undefined],
    ["the host's", "https://example.com"],
    ["another tenant's", "https://example.com/tenant2"],
    ["another host's", "https://evil.example/tenant1"],
    ["not a string", 7],
  ])("refuses a tenant document whose discovery_base is %s", async (_n, b) => {
    const { fetchFn } = server({
      [`https://example.com${WK}/tenant1`]: {
        ...doc("wss://x/wmp"),
        ...(b === undefined ? {} : { discovery_base: b }),
      },
    });
    await expect(
      discoverEndpoint("https://example.com/tenant1", fetchFn),
    ).rejects.toThrow(/not for https:\/\/example.com\/tenant1/);
  });

  it("refuses a host document that names a tenant", async () => {
    const { fetchFn } = server({
      [`https://example.com${WK}`]: doc("wss://x/wmp", "https://example.com/t"),
    });
    await expect(
      discoverEndpoint("https://example.com", fetchFn),
    ).rejects.toThrow(/not for https:\/\/example.com/);
  });

  it("accepts a host document that names the host", async () => {
    const { fetchFn } = server({
      [`https://example.com${WK}`]: doc("wss://x/wmp", "https://example.com/"),
    });
    const config = await discoverEndpoint("did:web:example.com", fetchFn);
    expect(config.endpoints.websocket).toBe("wss://x/wmp");
  });
});
