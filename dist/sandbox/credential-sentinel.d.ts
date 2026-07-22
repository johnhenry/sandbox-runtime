/**
 * Per-session sentinel registry for credential masking.
 *
 * A masked credential's real value is replaced inside the sandbox with a
 * sentinel of the form `fake_value_<uuid4>`. The sandboxed process sees only
 * the sentinel; the host-side proxy substitutes sentinel→real on egress to
 * allowlisted destinations. The map lives only in process memory — it is
 * never written to disk and never logged.
 */
import type { IncomingHttpHeaders } from 'node:http';
import type { SentinelBufferPair } from './body-substitution.js';
export declare const SENTINEL_PREFIX = "fake_value_";
/** Predicate matching a destination host against one injectHosts pattern. */
export type HostMatcher = (host: string, pattern: string) => boolean;
/**
 * Sentinel↔real-value map for one sandbox session, keyed by credential name.
 *
 * Each credential carries its own `injectHosts` list, and substitution is
 * gated per sentinel: a sentinel is swapped to its real value only when the
 * destination matches THAT credential's hosts. This prevents laundering
 * credential A through credential B's allowlisted host by sending A's
 * sentinel there — the proxy leaves A's sentinel intact on B's host.
 *
 * Keying on name (not value) means two env vars holding the same secret get
 * distinct sentinels, so each can have an independent host list.
 */
export declare class SentinelRegistry {
    private readonly byName;
    private readonly bySentinel;
    private allSentinelsPrefixed;
    /**
     * Return the sentinel for the credential named `name`, minting a fresh one
     * on first use. The sentinel is `fake_value_<uuid4>`: long enough that an
     * accidental collision with legitimate header content is negligible, and
     * free of shell/URL metacharacters so it survives `--setenv` and
     * `env NAME=value` unquoted.
     *
     * Idempotent on `name`: a repeat call returns the same sentinel and updates
     * `realValue`/`injectHosts` in place so `updateConfig()` can change either
     * without invalidating sentinels the sandboxed process has already read.
     * (A re-register whose new value has a different byte length leaves the
     * sentinel un-length-matched; body substitution then re-frames as chunked
     * rather than trusting a stale Content-Length.)
     */
    register(name: string, realValue: string, injectHosts: readonly string[]): string;
    /**
     * Like {@link register}, but with a caller-minted sentinel instead of the
     * default `fake_value_<uuid4>` — used when the fake must keep the real
     * value's shape (e.g. a structurally valid JWT for `decode: "jwt"`), so
     * client-side parsers inside the sandbox don't choke on it.
     *
     * Same idempotency contract as {@link register}: if `name` is already
     * registered, the EXISTING sentinel is returned (and `sentinel` discarded)
     * so a re-register never invalidates a fake the sandboxed process has
     * already read. The caller must mint sentinels with enough entropy that
     * collisions with real content are negligible (embed a uuid4). No
     * registered sentinel may be a substring of any other registered sentinel:
     * the body-substitution scan matches earliest-position-then-registration-
     * order, not longest-match, so nested sentinels would make replacement
     * chunk-boundary-dependent (still fail-safe — worst case a wrong fake
     * reaches upstream, never a secret).
     *
     * Caller-minted sentinels are used verbatim — never length-padded: a
     * shaped fake (e.g. a JWT) must keep its structure. They are therefore
     * generally not length-matched, and body substitution at hosts where they
     * inject falls back to chunked framing.
     */
    registerWithSentinel(name: string, sentinel: string, realValue: string, injectHosts: readonly string[]): string;
    /** Real value for `sentinel`, or undefined if not registered. */
    lookupReal(sentinel: string): string | undefined;
    /**
     * Names of the registered credentials whose `injectHosts` cover
     * `destHost`. Diagnostic helper: the proxy uses it to warn when a host is
     * exempted from TLS termination (so substitution can never run there) but
     * a masked credential is configured for injection at it.
     */
    namesInjectableAt(destHost: string, matches: HostMatcher): string[];
    /**
     * Sentinel→real byte pairs for every credential whose `injectHosts`
     * cover `destHost` — the substitution set the body transform scans for.
     * Same per-credential gating as {@link substituteInHeaders}. Buffers are
     * built per call so a re-registered credential's updated real value is
     * always current.
     */
    sentinelsForHost(destHost: string, matches: HostMatcher): SentinelBufferPair[];
    /** Iterate registered `[sentinel, realValue]` pairs. */
    entries(): IterableIterator<[string, string]>;
    /** Number of registered sentinels. */
    get size(): number;
    /** Drop every mapping. Called on session teardown. */
    clear(): void;
    /**
     * Replace registered sentinels found in `headers` with their real values,
     * in place. Each sentinel substitutes only when `destHost` matches one of
     * THAT credential's `injectHosts` patterns (via `matches`); a sentinel
     * whose host list does not cover `destHost` is left as the useless fake.
     *
     * Scans all header values rather than a fixed set — a sentinel showing up
     * anywhere is the substitution trigger, regardless of header name
     * (Authorization, X-Api-Key, Private-Token, ...).
     *
     * The caller remains responsible for transport gating (TLS-terminated path
     * unless `allowPlaintextInject`).
     */
    substituteInHeaders(headers: IncomingHttpHeaders, destHost: string, matches: HostMatcher): void;
    private substituteInString;
}
//# sourceMappingURL=credential-sentinel.d.ts.map