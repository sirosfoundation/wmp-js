/**
 * WMP endpoint discovery — mirrors go-wmp/pkg/wmp/discovery.go.
 */

/**
 * Well-known WMP configuration as served at /.well-known/wmp-configuration,
 * or below it for a tenant.
 */
export interface WellKnownConfig {
  /**
   * The discovery base the document describes:
   * `https://<host><tenant-path>`. Required for a tenant path.
   */
  discovery_base?: string;
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
 * Where the well-known configuration of a domain-based identifier is found
 * (WMP Core 7.5.1): a host and, for a tenant of a host that serves several
 * providers, the tenant's path.
 */
export interface DiscoveryBase {
  /** The host, with its port when the identifier names one. */
  host: string;
  /** Empty for the whole host; otherwise starts with "/", no trailing "/". */
  tenantPath: string;
}

const HOST_RE =
  /^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*(:\d{1,5})?$/i;
const IPV6_HOST_RE = /^\[[0-9a-f:.]+\](:\d{1,5})?$/i;

function hostBase(host: string): DiscoveryBase | null {
  if (host.length > 259 || !(HOST_RE.test(host) || IPV6_HOST_RE.test(host))) {
    return null;
  }
  return { host, tenantPath: "" };
}

/**
 * The base of an https URL, read from the string as written: `URL` would
 * resolve dot segments and drop an empty query, and the identifier is what
 * the tenant path is compared with.
 */
function urlBase(raw: string): DiscoveryBase | null {
  if (!raw.startsWith("https://") || /[?#\\\s]/.test(raw)) {
    return null;
  }
  const rest = raw.slice("https://".length);
  const slash = rest.indexOf("/");
  const base = hostBase(slash < 0 ? rest : rest.slice(0, slash));
  if (!base) {
    return null;
  }
  let end = rest.length;
  while (slash >= 0 && end > slash && rest[end - 1] === "/") {
    end--;
  }
  const tenantPath = slash < 0 ? "" : rest.slice(slash, end);
  for (const segment of tenantPath.split("/")) {
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      return null;
    }
    if (decoded === "." || decoded === "..") {
      return null;
    }
  }
  return { host: base.host, tenantPath };
}

/**
 * Derive the discovery base of an identifier, or `null` when it has none.
 *
 *     x509:san:dns:example.com                -> example.com
 *     https://example.com/tenant1             -> example.com, /tenant1
 *     x509:san:uri:https://example.com/tenant -> example.com, /tenant
 *     did:web:example.com                     -> example.com
 *
 * A did:web identifier with a path has none: the did:web method resolves it
 * through its DID Document, whose WMPMessaging service names the endpoint
 * (WMP Core 7.5.4). An identifier with a query, a fragment, userinfo or a
 * "." or ".." path segment has none either.
 */
export function discoveryBase(identifier: string): DiscoveryBase | null {
  if (identifier.startsWith("x509:san:dns:")) {
    return hostBase(identifier.slice("x509:san:dns:".length));
  }
  if (identifier.startsWith("x509:san:uri:")) {
    return urlBase(identifier.slice("x509:san:uri:".length));
  }
  if (identifier.startsWith("https://")) {
    return urlBase(identifier);
  }
  if (identifier.startsWith("did:web:")) {
    const parts = identifier.slice("did:web:".length).split(":");
    if (parts.length !== 1) {
      return null;
    }
    try {
      return hostBase(decodeURIComponent(parts[0]));
    } catch {
      return null;
    }
  }
  return null;
}

/**
 * The URL of a base's configuration: the well-known segment inserted between
 * the host and the tenant path, as RFC 8414 Section 3.1 does.
 */
export function wellKnownUrl(base: DiscoveryBase): string {
  return `https://${base.host}/.well-known/wmp-configuration${base.tenantPath}`;
}

/** Whether a configuration describes the base it was fetched for. */
function describesBase(config: WellKnownConfig, base: DiscoveryBase): boolean {
  if (config.discovery_base === undefined || config.discovery_base === "") {
    return base.tenantPath === "";
  }
  if (typeof config.discovery_base !== "string") {
    return false;
  }
  // The scheme compares case-insensitively, like the host.
  const got = urlBase(config.discovery_base.replace(/^https:/i, "https:"));
  return (
    got !== null &&
    got.host.toLowerCase() === base.host.toLowerCase() &&
    got.tenantPath === base.tenantPath
  );
}

/**
 * Fetch the well-known WMP configuration for a domain-based WMP identifier.
 *
 * The configuration is fetched at exactly the URL of the identifier's
 * discovery base ({@link discoveryBase}, {@link wellKnownUrl}):
 * `https://host/tenant1` resolves at
 * `https://host/.well-known/wmp-configuration/tenant1`. A tenant never gets
 * its host's configuration, and the document's `discovery_base` must name
 * the base: required for a tenant, checked when present for a whole host.
 *
 * Throws if the identifier has no discovery base, the fetch fails, or the
 * document is for another base.
 */
export async function discoverEndpoint(
  identifier: string,
  fetchFn: typeof globalThis.fetch = globalThis.fetch.bind(globalThis),
): Promise<WellKnownConfig> {
  const base = discoveryBase(identifier);
  if (!base) {
    throw new Error(
      `Identifier "${identifier}" has no discovery base: use session parameters or a profile resolver`,
    );
  }
  const url = wellKnownUrl(base);
  const resp = await fetchFn(url, { headers: { Accept: "application/json" } });
  if (!resp.ok) {
    throw new Error(`WMP discovery failed for ${url}: HTTP ${resp.status}`);
  }
  const config = (await resp.json()) as WellKnownConfig;
  if (config === null || typeof config !== "object" || !describesBase(config, base)) {
    throw new Error(
      `WMP discovery failed for ${url}: the configuration is not for https://${base.host}${base.tenantPath}`,
    );
  }
  return config;
}
