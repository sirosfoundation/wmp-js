/**
 * Locates and loads the WMP spec vectors for the test suites. Mirrors go-wmp's
 * vectorsDir(): WMP_VECTORS_DIR overrides the search, otherwise the sibling
 * ../wmp/vectors checkout is used.
 *
 * Unlike go-wmp (which skips), a missing vectors directory FAILS: a harness
 * that silently skips its conformance suite proves nothing, in CI least of all.
 */

import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import { resolve } from "node:path";

export function vectorsDir(): string {
  const env = process.env.WMP_VECTORS_DIR;
  const candidates = env
    ? [resolve(env)]
    : [resolve(__dirname, "../../wmp/vectors"), resolve(process.cwd(), "../wmp/vectors")];
  const dir = candidates.find((p) => existsSync(resolve(p, "manifest.json")));
  if (!dir) {
    throw new Error(
      `WMP vectors not found (looked for manifest.json in ${candidates.join(", ")}); ` +
        "check out sirosfoundation/wmp as a sibling of this repository or set WMP_VECTORS_DIR",
    );
  }
  return dir;
}

/**
 * The spec directory (the one that holds wmp-core.md). WMP_SPEC_DIR overrides;
 * otherwise it is the sibling "spec" of the vectors directory, looked up from the
 * vectors directory's real path first (a symlinked vectors directory sits in
 * another tree than the checkout it points into) and then as written, then the
 * sibling checkout. It fails when none holds wmp-core.md.
 */
export function specDir(): string {
  const vectors = vectorsDir();
  const candidates = [
    process.env.WMP_SPEC_DIR,
    resolve(realpathSync(vectors), "..", "spec"),
    resolve(vectors, "..", "spec"),
    resolve(__dirname, "../../wmp/spec"),
  ].filter((c): c is string => !!c).map((c) => resolve(c));
  const dir = candidates.find((c) => existsSync(resolve(c, "wmp-core.md")));
  if (!dir) {
    throw new Error(`WMP spec not found (looked for wmp-core.md in ${candidates.join(", ")}); set WMP_SPEC_DIR`);
  }
  return dir;
}

export type VectorKind = "rpc" | "interop" | "transport-http";

export interface ManifestEntry {
  file: string;
  kind: VectorKind;
}

export function loadManifest(): ManifestEntry[] {
  const raw = JSON.parse(readFileSync(resolve(vectorsDir(), "manifest.json"), "utf8")) as {
    files: ManifestEntry[];
  };
  return raw.files;
}

/** Top-level vector files present in the directory (everything but manifest/schema). */
export function vectorFilesOnDisk(): string[] {
  return readdirSync(vectorsDir())
    .filter((f) => f.endsWith(".json") && f !== "manifest.json" && f !== "vector-schema.json")
    .sort();
}

/** Vector members shared by every kind. */
export interface TestVector {
  id: string;
  description: string;
  conformance_level: string;
  kind?: VectorKind;
  setup?: { supported_versions?: string[]; event_buffer?: number; principals?: Record<string, string> };
  input: unknown;
  expected_response?: unknown;
  expected_error?: unknown;
  expected_replay?: unknown;
  must_refuse?: boolean;
  handler_action?: unknown;
  peer_options?: unknown;
  notes?: string;
}

/** Loads a vector file; throws when it is missing or not an array. */
export function loadVectors<T = TestVector>(filename: string): T[] {
  const path = resolve(vectorsDir(), filename);
  if (!existsSync(path)) throw new Error(`vector file ${path} is missing`);
  const data = JSON.parse(readFileSync(path, "utf8")) as unknown;
  if (!Array.isArray(data)) throw new Error(`${filename}: expected a JSON array`);
  return data as T[];
}
