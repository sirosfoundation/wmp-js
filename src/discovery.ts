/**
 * WMP endpoint discovery — mirrors go-wmp/pkg/wmp/discovery.go.
 */

/** Well-known WMP configuration as served at /.well-known/wmp-configuration. */
export interface WellKnownConfig {
  supported_versions: string[];
  endpoints: Record<string, string>;
  security_modes: string[];
  capabilities?: Record<string, unknown>;
  accepted_schemes?: string[];
  mls_key_packages?: string;
  relay?: string;
  identity_providers?: string[];
  trust_frameworks?: string[];
  erds?: ErdsMetadata;
  recipient_metadata?: RecipientMetadata;
}

export interface ErdsMetadata {
  consignment_modes?: string[];
  assurance_levels?: string[];
  supported_policies?: string[];
  delegation?: boolean;
  evidence_repository?: string;
  evidence_retention?: string;
  scheduled_delivery?: boolean;
}

export interface RecipientMetadata {
  accepted_content_types?: string[];
  max_message_size?: number;
  consignment_preferences?: string;
  encryption_required?: boolean;
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
    let domain: string;
    try {
      domain = decodeURIComponent(rest.split(":")[0]);
    } catch {
      return "";
    }
    // Reject empty, overly long, or malformed hostnames.
    if (
      !domain ||
      domain.length > 253 ||
      !/^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$/i.test(
        domain,
      )
    ) {
      return "";
    }
    return domain;
  }
  return "";
}

/**
 * Fetch the well-known WMP configuration for any WMP identifier.
 *
 * For a full URL (e.g. `https://host/wmp-engine/wmp`), tries the well-known
 * at the URL's own path prefix FIRST (`https://host/wmp-engine/.well-known/
 * wmp-configuration`) — path-prefixed deployments (a reverse proxy's
 * location) serve it there — and falls back to the domain root.
 * For bare identifiers (domains, DIDs), fetches the domain root.
 *
 * Throws if no domain can be extracted or every fetch fails.
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
  // The candidate well-known URLs, first-wins: the URL's own path prefix
  // (a reverse-proxied deployment), then the domain root.
  const candidates: string[] = [];
  if (identifier.startsWith("https://")) {
    try {
      const url = new URL(identifier);
      const path = url.pathname.replace(/\/+$/, "").replace(/\/wmp$/, "");
      if (path && path !== "/") {
        candidates.push(`${url.origin}${path}/.well-known/wmp-configuration`);
      }
    } catch {
      // fall through to the domain root
    }
  }
  candidates.push(`https://${domain}/.well-known/wmp-configuration`);
  let lastError: unknown;
  for (const url of candidates) {
    try {
      const resp = await fetchFn(url, {
        headers: { Accept: "application/json" },
      });
      if (resp.ok) {
        return (await resp.json()) as WellKnownConfig;
      }
      lastError = new Error(`WMP discovery failed for ${url}: HTTP ${resp.status}`);
    } catch (err) {
      lastError = err;
    }
  }
  throw lastError instanceof Error
    ? lastError
    : new Error(`WMP discovery failed for ${identifier}`);
}
