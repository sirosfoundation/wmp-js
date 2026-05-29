/**
 * WMP endpoint discovery — mirrors go-wmp/pkg/wmp/discovery.go.
 */

/** Well-known WMP configuration as served at /.well-known/wmp-configuration. */
export interface WellKnownConfig {
  supported_versions: string[];
  endpoints: Record<string, string>;
  security_modes: string[];
  capabilities?: Record<string, unknown>;
  identity_providers?: string[];
  trust_frameworks?: string[];
}

/**
 * Extract the domain from a WMP identifier.
 *
 * Supports x509:san:dns, x509:san:uri, https://, and did:web schemes.
 * Returns an empty string if the scheme is not recognised (e.g. did:key).
 */
export function extractDomain(identifier: string): string {
  if (identifier.startsWith("x509:san:dns:")) {
    return identifier.slice("x509:san:dns:".length);
  }
  if (identifier.startsWith("x509:san:uri:")) {
    try {
      const url = new URL(identifier.slice("x509:san:uri:".length));
      return url.hostname;
    } catch {
      return "";
    }
  }
  if (identifier.startsWith("https://")) {
    try {
      const url = new URL(identifier);
      return url.hostname;
    } catch {
      return "";
    }
  }
  if (identifier.startsWith("did:web:")) {
    const rest = identifier.slice("did:web:".length);
    const domain = rest.split(":")[0];
    return decodeURIComponent(domain);
  }
  return "";
}

/**
 * Fetch the well-known WMP configuration for any WMP identifier.
 *
 * Extracts the domain and fetches `https://<domain>/.well-known/wmp-configuration`.
 * Throws if no domain can be extracted or the fetch fails.
 */
export async function discoverEndpoint(
  identifier: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch.bind(globalThis),
): Promise<WellKnownConfig> {
  const domain = extractDomain(identifier);
  if (!domain) {
    throw new Error(
      `Cannot extract domain from identifier "${identifier}": use session parameters or a profile resolver`,
    );
  }
  const url = `https://${domain}/.well-known/wmp-configuration`;
  const resp = await fetchFn(url, {
    headers: { Accept: "application/json" },
  });
  if (!resp.ok) {
    throw new Error(`WMP discovery failed for ${url}: HTTP ${resp.status}`);
  }
  return (await resp.json()) as WellKnownConfig;
}
