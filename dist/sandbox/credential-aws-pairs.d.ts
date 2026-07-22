/**
 * Linked AWS credential pairs for SigV4 re-signing.
 *
 * The sentinel registry maps independent name→value fakes, but SigV4
 * needs the access key id, secret access key, and optional session token
 * linked as ONE credential: the signature is an HMAC derived from the
 * secret, so a request signed with the fake secret must be re-signed with
 * the real one — and the only reliable trigger is the fake access key id
 * appearing in the signature's credential scope.
 *
 * Pairs come from two sources (see {@link registerAwsPairs}):
 * - an explicit `credentials.awsPairs` grouping, for non-standard
 *   variable names;
 * - auto-detection of the conventional AWS_ACCESS_KEY_ID /
 *   AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN trio when those vars are
 *   masked whole-value — the names the AWS SDKs and CLI actually read, so
 *   masking them is the opt-in.
 *
 * {@link createSigv4Planner} builds the per-request hook the
 * TLS-terminating proxy runs: exact-match the referenced access key id
 * against registered pair sentinels, classify the signature shape, and
 * either plan a re-sign (header-sigv4) or apply the configured
 * deny/passthrough policy (streaming, presigned, sigv4a).
 */
import type { IncomingHttpHeaders } from 'node:http';
import type { HostMatcher } from './credential-sentinel.js';
import type { AwsPairConfig, CredentialEnvVarConfig, Sigv4Config } from './sandbox-config.js';
/** Conventional env var names the AWS SDKs and CLI read credentials from. */
export declare const AWS_ACCESS_KEY_ID_VAR = "AWS_ACCESS_KEY_ID";
export declare const AWS_SECRET_ACCESS_KEY_VAR = "AWS_SECRET_ACCESS_KEY";
export declare const AWS_SESSION_TOKEN_VAR = "AWS_SESSION_TOKEN";
export interface AwsCredentialPair {
    /** The fake access key id the sandboxed process holds (the sentinel). */
    readonly accessKeyIdSentinel: string;
    readonly realAccessKeyId: string;
    readonly realSecretAccessKey: string;
    readonly realSessionToken?: string;
    /**
     * Hosts where the pair may be injected — the access-key-id entry's
     * effective injectHosts. Requests to other hosts keep the fake
     * signature untouched, same as ordinary sentinel substitution.
     */
    readonly injectHosts: readonly string[];
}
/**
 * AWS pairs for one sandbox session, keyed by the access-key-id sentinel.
 * Like the sentinel registry, it lives only in process memory — never
 * written to disk, never logged.
 */
export declare class AwsPairRegistry {
    private readonly bySentinel;
    /** Insert or replace the pair keyed on its access-key-id sentinel. */
    register(pair: AwsCredentialPair): void;
    /** Exact-match lookup by the fake access key id; never pattern-based. */
    lookup(accessKeyIdSentinel: string): AwsCredentialPair | undefined;
    get size(): number;
    /** Drop every pair. Called on session teardown. */
    clear(): void;
}
/**
 * Register AWS credential pairs from the masked env vars.
 *
 * Runs after `buildMaskedEnvVars`: `setEnvVars` maps each masked variable
 * to its fake in-sandbox value, which for whole-value masking IS the
 * sentinel. Pair specs are the explicit `credentials.awsPairs` entries
 * plus — when none of them claims a conventional name — an implicit
 * AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN spec.
 *
 * A spec registers only when both the access-key-id and secret variables
 * were actually masked (present in the host env, whole-value entries in
 * `setEnvVars`); the session token joins the pair when its variable was
 * masked too. A partially available spec is skipped — with one loud
 * warning for the dangerous half-masking: a masked secret without a
 * masked access key id means SigV4 requests carry a real key id (so
 * nothing triggers re-signing) over a fake-secret signature that can
 * never verify.
 */
export declare function registerAwsPairs(envVars: readonly CredentialEnvVarConfig[], awsPairs: readonly AwsPairConfig[] | undefined, allowedDomains: readonly string[], setEnvVars: Readonly<Record<string, string>>, registry: AwsPairRegistry, env?: Record<string, string | undefined>): void;
export type Sigv4Policy = 'deny' | 'passthrough';
export declare function resolveSigv4Policies(config: Sigv4Config | undefined): {
    streaming: "deny" | "passthrough";
    presigned: "deny" | "passthrough";
    sigv4a: "deny" | "passthrough";
};
/** Decision for one request, produced before header substitution runs. */
export type Sigv4Plan = {
    action: 'deny';
    reason: string;
} | {
    action: 'resign';
    /**
     * Payload hash to sign. `undefined` means the client signed a
     * literal body hash (or none): the caller must buffer the body,
     * SHA-256 it, and pass the hex digest to `apply` — the hash must
     * cover the bytes actually sent upstream.
     */
    payloadHash: string | undefined;
    /**
     * Mutate the outgoing (post-substitution) headers in place:
     * replace Authorization with the real-credential signature, pin
     * x-amz-content-sha256 to the signed hash, and inject the real
     * session token when the pair carries one.
     */
    apply(headers: IncomingHttpHeaders, hostHeader: string, payloadHash: string): void;
};
/**
 * Per-request SigV4 hook for the TLS-terminating proxy. Returns
 * `undefined` when the request is not the re-signer's to handle (no
 * SigV4 signature, unknown/real access key id, destination outside the
 * pair's injectHosts, or a passthrough policy) — the proxy then forwards
 * it exactly as before this feature existed.
 *
 * Must be called with the ORIGINAL client headers, before sentinel
 * substitution: detection matches the fake access key id, which
 * substitution would have already replaced.
 */
export type PlanSigv4 = (method: string, requestTarget: string, headers: IncomingHttpHeaders, destHost: string) => Sigv4Plan | undefined;
/**
 * Build the {@link PlanSigv4} hook from the session's pair registry and
 * configured policies. `matches` is the same host matcher used for
 * sentinel substitution, so injectHosts gating is consistent across both.
 */
export declare function createSigv4Planner(registry: AwsPairRegistry, config: Sigv4Config | undefined, matches: HostMatcher): PlanSigv4;
//# sourceMappingURL=credential-aws-pairs.d.ts.map