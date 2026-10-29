/**
 * Protocol version negotiation (Core Section 2.2.2) — mirrors
 * go-wmp/pkg/wmp/version.go (v0.11.0).
 */

import { WMPError } from "./jsonrpc.js";
import { ErrorCode } from "./types.js";

/** Versions this library speaks. */
export const SUPPORTED_VERSIONS: readonly string[] = ["0.1"];

/** One decimal component: digits only, no leading zero ("0.01" is malformed), at most 6 digits. */
function parsePart(s: string): number | undefined {
  if (s === "" || s.length > 6 || (s.length > 1 && s[0] === "0")) return undefined;
  return /^[0-9]+$/.test(s) ? Number(s) : undefined;
}

/**
 * Parses a "MAJOR.MINOR" version. Both parts are plain decimal digits without
 * leading zeros; signs, spaces, empty parts and extra components are rejected.
 */
export function parseVersion(v: unknown): { major: number; minor: number } | undefined {
  if (typeof v !== "string") return undefined;
  const i = v.indexOf(".");
  if (i < 0) return undefined;
  const major = parsePart(v.slice(0, i));
  const minor = parsePart(v.slice(i + 1));
  return major === undefined || minor === undefined ? undefined : { major, minor };
}

/**
 * Returns the highest version in `supported` that has the same MAJOR as
 * `offered` and a MINOR that is not greater than offered's, as the entry from
 * `supported`, unmodified (minors compare numerically: "0.10" is above "0.9").
 * Undefined when `offered` is not a valid version or nothing is compatible; the
 * caller then rejects with {@link versionRejection}. Unparseable entries in
 * `supported` are ignored.
 */
export function negotiateVersion(offered: string, supported: readonly string[]): string | undefined {
  const off = parseVersion(offered);
  if (!off) return undefined;
  let best = -1;
  let selected: string | undefined;
  for (const s of supported) {
    const v = parseVersion(s);
    if (!v || v.major !== off.major || v.minor > off.minor || v.minor <= best) continue;
    best = v.minor;
    selected = s;
  }
  return selected;
}

/**
 * The error for an offered version that {@link negotiateVersion} could not
 * match: -32602 when it is not a valid "MAJOR.MINOR" string (including an
 * absent one), else -31013 carrying supported_versions (Core 2.2.2 and 3.8).
 */
export function versionRejection(offered: unknown, supported: readonly string[]): WMPError {
  if (!parseVersion(offered)) return new WMPError(ErrorCode.InvalidParams, "Invalid params");
  return new WMPError(ErrorCode.VersionNotSupported, "Version not supported", { supported_versions: [...supported] });
}
