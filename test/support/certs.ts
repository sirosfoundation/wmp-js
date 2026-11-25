/** Certificate-shaped DER around a public key, for tests that leave chain validation to the caller. */

function tlv(tag: number, ...parts: Uint8Array[]): Uint8Array {
  const len = parts.reduce((n, p) => n + p.length, 0);
  let head: number[];
  if (len < 128) head = [tag, len];
  else if (len < 256) head = [tag, 0x81, len];
  else head = [tag, 0x82, len >> 8, len & 0xff];
  const out = new Uint8Array(head.length + len);
  out.set(head);
  let at = head.length;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export async function certFor(pub: CryptoKey): Promise<Uint8Array> {
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", pub));
  const empty = tlv(0x30);
  const tbs = tlv(0x30, tlv(0xa0, tlv(0x02, new Uint8Array([2]))), tlv(0x02, new Uint8Array([1])), empty, empty, empty, empty, spki);
  return tlv(0x30, tbs, empty, tlv(0x03, new Uint8Array([0])));
}

export function ecKey(curve = "P-256"): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);
}
