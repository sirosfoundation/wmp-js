import { describe, it, expect, vi } from "vitest";
import {
  canonicalize,
  contentObject,
  signContent,
  verifyContentSignature,
  ContentSignatureError,
} from "../src/signature.js";
import { webCryptoProofSigner, type RequestProofSigner } from "../src/proof.js";
import { certFor, ecKey } from "./support/certs.js";

const b64url = (b: Uint8Array) => Buffer.from(b).toString("base64url");
const header = (sig: string) => JSON.parse(Buffer.from(sig.split(".")[0], "base64url").toString("utf8"));

async function fixture(curve = "P-256") {
  const keys = await ecKey(curve);
  const signer = webCryptoProofSigner(keys.privateKey);
  const x5c = [await certFor(keys.publicKey)];
  return { keys, signer, x5c };
}

describe("canonicalize (RFC 8785)", () => {
  it("serialises the sample of section 3.2.2 as section 3.2.4 lists it", () => {
    const input = JSON.parse(
      '{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],' +
        '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",' +
        '"literals": [null, true, false]}',
    );
    expect(canonicalize(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it("sorts property names by UTF-16 code units (section 3.2.3)", () => {
    const input = JSON.parse(
      String.raw`{
        "€": "Euro Sign",
        "\r": "Carriage Return",
        "דּ": "Hebrew Letter Dalet With Dagesh",
        "1": "One",
        "😀": "Emoji: Grinning Face",
        "\u0080": "Control",
        "ö": "Latin Small Letter O With Diaeresis"
      }`,
    );
    const order = [...canonicalize(input).matchAll(/:"([^"]+)"/g)].map((m) => m[1]);
    expect(order).toEqual([
      "Carriage Return",
      "One",
      "Control",
      "Latin Small Letter O With Diaeresis",
      "Euro Sign",
      "Emoji: Grinning Face",
      "Hebrew Letter Dalet With Dagesh",
    ]);
  });

  it("leaves out members without a value and nests", () => {
    expect(canonicalize({ b: [{ z: 1, a: undefined }], a: { y: "x" } })).toBe('{"a":{"y":"x"},"b":[{"z":1}]}');
  });

  it.each([
    ["NaN", Number.NaN],
    ["Infinity", Number.POSITIVE_INFINITY],
    ["a bigint", 1n],
    ["a function", () => 1],
    ["a lone surrogate", "\ud800"],
    ["a class instance", new Date(0)],
    ["undefined in an array", [undefined]],
  ])("refuses %s", (_name, value) => {
    expect(() => canonicalize({ v: value })).toThrow(TypeError);
  });
});

describe("contentObject", () => {
  it("is params without wmp", () => {
    expect(contentObject({ wmp: { version: "0.1" }, ciphertext: "abc", plaintext_hash: { algorithm: "sha-256", value: "x" } })).toEqual({
      ciphertext: "abc",
      plaintext_hash: { algorithm: "sha-256", value: "x" },
    });
  });
});

describe("content signature (WMP Core 5.4)", () => {
  const content = { to: ["x509:san:dns:bob.example.com"], content_type: "application/json", body: { n: 1 } };

  it("makes a detached JWS with an unencoded payload and a raw R||S signature", async () => {
    const { signer, x5c, keys } = await fixture();
    const sig = await signContent(content, { signer, x5c });
    const parts = sig.split(".");
    expect(parts).toHaveLength(3);
    expect(parts[1]).toBe("");
    expect(header(sig)).toEqual({ alg: "ES256", b64: false, crit: ["b64"], x5c: [Buffer.from(x5c[0]).toString("base64")] });
    expect(Buffer.from(parts[2], "base64url")).toHaveLength(64);
    // The signing input is ASCII(header) || "." || JCS(content), the payload not base64url-encoded.
    const input = new TextEncoder().encode(`${parts[0]}.${canonicalize(content)}`);
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, keys.publicKey, Buffer.from(parts[2], "base64url"), input);
    expect(ok).toBe(true);
  });

  it.each(["P-256", "P-384", "P-521"])("round-trips on %s whatever the member order", async (curve) => {
    const { signer, x5c } = await fixture(curve);
    const sig = await signContent(content, { signer, x5c, kid: "key-1" });
    const verifyChain = vi.fn();
    const reordered = { body: { n: 1 }, content_type: "application/json", to: ["x509:san:dns:bob.example.com"] };
    const v = await verifyContentSignature(sig, reordered, { verifyChain });
    expect(v.kid).toBe("key-1");
    expect(Buffer.from(v.chain![0]).equals(Buffer.from(x5c[0]))).toBe(true);
    expect(verifyChain).toHaveBeenCalledOnce();
  });

  it("round-trips an EdDSA signature named by kid", async () => {
    const keys = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"])) as CryptoKeyPair;
    const sig = await signContent(content, { signer: webCryptoProofSigner(keys.privateKey), kid: "did:web:alice.example.com#key-1" });
    expect(header(sig)).toEqual({ alg: "EdDSA", b64: false, crit: ["b64"], kid: "did:web:alice.example.com#key-1" });
    const v = await verifyContentSignature(sig, content, { resolveKey: (kid) => (kid.endsWith("#key-1") ? keys.publicKey : undefined) });
    expect(v.alg).toBe("EdDSA");
    await expect(verifyContentSignature(sig, content, { resolveKey: () => undefined })).rejects.toThrow(/kid does not resolve/);
    await expect(verifyContentSignature(sig, content, {})).rejects.toThrow(/kid signatures are not accepted/);
  });

  it("requires a key reference to sign", async () => {
    const { signer } = await fixture();
    await expect(signContent(content, { signer })).rejects.toThrow(/x5c and kid/);
  });

  it("refuses changed content", async () => {
    const { signer, x5c } = await fixture();
    const sig = await signContent(content, { signer, x5c });
    await expect(verifyContentSignature(sig, { ...content, body: { n: 2 } }, { verifyChain: () => {} })).rejects.toThrow(
      ContentSignatureError,
    );
  });

  it("refuses a chain it has no trust anchors for, and a chain the anchors reject", async () => {
    const { signer, x5c } = await fixture();
    const sig = await signContent(content, { signer, x5c });
    await expect(verifyContentSignature(sig, content, {})).rejects.toThrow(/x5c signatures are not accepted/);
    await expect(
      verifyContentSignature(sig, content, {
        verifyChain: () => {
          throw new Error("unknown issuer");
        },
      }),
    ).rejects.toThrow(/certificate chain: unknown issuer/);
  });

  it("refuses a DER-encoded ECDSA signature", async () => {
    const { keys, x5c } = await fixture();
    const der: RequestProofSigner = {
      alg: "ES256",
      sign: async (input) => {
        const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, input as BufferSource));
        const int = (b: Uint8Array) => {
          let i = 0;
          while (i < b.length - 1 && b[i] === 0) i++;
          const v = b[i] & 0x80 ? [0, ...b.slice(i)] : [...b.slice(i)];
          return [0x02, v.length, ...v];
        };
        const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
        return new Uint8Array([0x30, body.length, ...body]);
      },
    };
    const sig = await signContent(content, { signer: der, x5c });
    await expect(verifyContentSignature(sig, content, { verifyChain: () => {} })).rejects.toThrow(/signature length/);
  });

  it.each<[string, (h: Record<string, unknown>) => void, RegExp]>([
    ["b64 true", (h) => void (h.b64 = true), /b64/],
    ["b64 absent", (h) => void delete h.b64, /b64/],
    ["crit absent", (h) => void delete h.crit, /crit/],
    ["an unknown critical parameter", (h) => void (h.crit = ["b64", "exp"]), /crit/],
    ["alg none", (h) => void (h.alg = "none"), /algorithm/],
    ["alg null", (h) => void (h.alg = null), /algorithm/],
    ["x5c null", (h) => void (h.x5c = null), /x5c/],
    ["an empty x5c", (h) => void (h.x5c = []), /x5c/],
    ["kid null", (h) => void (h.kid = null), /kid/],
    ["no key reference", (h) => void delete h.x5c, /names no key/],
  ])("refuses a header with %s", async (_name, mutate, reason) => {
    // The signature is made over the mutated header, so only the header rule can refuse it.
    const { keys, x5c } = await fixture();
    const h: Record<string, unknown> = { alg: "ES256", b64: false, crit: ["b64"], x5c: [Buffer.from(x5c[0]).toString("base64")] };
    mutate(h);
    const head = b64url(new TextEncoder().encode(JSON.stringify(h)));
    const input = new TextEncoder().encode(`${head}.${canonicalize(content)}`);
    const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, keys.privateKey, input));
    await expect(verifyContentSignature(`${head}..${b64url(raw)}`, content, { verifyChain: () => {}, resolveKey: () => keys.publicKey })).rejects.toThrow(
      reason,
    );
  });

  it.each([
    ["an attached payload", (s: string) => s.replace("..", ".e30.")],
    ["two segments", (s: string) => s.replace("..", ".")],
    ["an empty signature", (s: string) => s.slice(0, s.indexOf("..") + 2)],
    ["a non-canonical encoding", (s: string) => `${s}=`],
  ])("refuses %s", async (_name, mutate) => {
    const { signer, x5c } = await fixture();
    const sig = await signContent(content, { signer, x5c });
    await expect(verifyContentSignature(mutate(sig), content, { verifyChain: () => {} })).rejects.toThrow(ContentSignatureError);
  });

  it("refuses an algorithm outside the accepted list", async () => {
    const { signer, x5c } = await fixture();
    const sig = await signContent(content, { signer, x5c });
    await expect(verifyContentSignature(sig, content, { verifyChain: () => {}, algorithms: ["EdDSA"] })).rejects.toThrow(/algorithm/);
  });
});
