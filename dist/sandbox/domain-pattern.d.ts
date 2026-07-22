/**
 * Domain-pattern matching shared between runtime host filtering
 * (sandbox-manager) and config-time validation (sandbox-config).
 * Lives in its own module so the schema can import it without pulling
 * in sandbox-manager (which imports the schema — circular).
 */
/**
 * Match a hostname against a domain pattern.
 *
 * Patterns:
 *   - `*` matches everything (deny-all; the schema only accepts this in
 *     deniedDomains).
 *   - `*.example.com` matches any strict subdomain of example.com.
 *   - anything else matches exactly (case-insensitive).
 *
 * Wildcard suffix matching is refused for IP literals so an IPv6 zone-ID
 * payload like `::ffff:1.2.3.4%x.allowed.com` cannot pass `.endsWith()`
 * while the OS connects to the bare IP. isValidHost already rejects `%`,
 * but we refuse here too for defence in depth.
 */
export declare function matchesDomainPattern(hostname: string, pattern: string): boolean;
/**
 * Decide whether a per-credential `injectHosts` entry is reachable via
 * `network.allowedDomains` — i.e. every concrete host that could match
 * `injectHost` is allowed by at least one entry in `allowedDomains`.
 *
 * For an exact `injectHost` (`api.github.com`) this is just
 * `matchesDomainPattern` against each allowed pattern.
 *
 * For a wildcard `injectHost` (`*.X`), an exact allowedDomain can never
 * cover it (it admits only one host), so coverage requires an allowed
 * wildcard `*.Y` whose base is `X` or an ancestor of `X` — e.g.
 * `*.api.github.com` is covered by `*.github.com`.
 */
export declare function isInjectHostCoveredByAllowedDomains(injectHost: string, allowedDomains: readonly string[]): boolean;
//# sourceMappingURL=domain-pattern.d.ts.map