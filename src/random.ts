/** Cryptographically secure random bytes (browser, Node 20+, workers). */
export function getRandomValues(n: number): Uint8Array {
  const c = (globalThis as { crypto?: { getRandomValues?: (a: Uint8Array) => Uint8Array } }).crypto;
  if (!c?.getRandomValues) throw new Error("no secure random source available");
  return c.getRandomValues(new Uint8Array(n));
}
