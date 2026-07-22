import type { Socket } from 'node:net';
import type { Duplex } from 'node:stream';
import type { Server } from 'node:http';
import { type MitmCA } from './mitm-ca.js';
import { type FilterRequestCallback, type MutateForwardedHeaders } from './request-filter.js';
import { type GetBodySubstitutions } from './body-substitution.js';
import type { PlanSigv4 } from './credential-aws-pairs.js';
import type { ResolvedParentProxy } from './parent-proxy.js';
export interface HttpProxyServerOptions {
    filter(port: number, host: string, socket: Socket | Duplex): Promise<boolean> | boolean;
    /**
     * Optional function to get the MITM proxy socket path for a given host.
     * If returns a socket path, the request will be routed through that MITM proxy.
     * If returns undefined, the request will be handled directly.
     */
    getMitmSocketPath?(host: string): string | undefined;
    /**
     * If present, CONNECT requests are TLS-terminated in-process and the
     * decrypted HTTP forwarded upstream over real TLS, instead of opening an
     * opaque byte tunnel. Mutually exclusive with getMitmSocketPath at the
     * config layer (sandbox-manager rejects both being set).
     */
    mitmCA?: MitmCA;
    /**
     * Per-host opt-out of TLS termination; consulted only when `mitmCA` is
     * set. Return false to leave that CONNECT as an opaque byte tunnel
     * (still hostname-allowlisted via `filter`, but not content-inspected —
     * the same posture as the non-tlsTerminate path), so the sandboxed
     * client performs its own TLS handshake end-to-end with the upstream.
     *
     * Use for upstreams the proxy must not re-originate: mTLS services
     * (only the in-sandbox client holds the client certificate) and
     * certificate-pinning clients that reject the MITM CA. Note that
     * `filterRequest` and `mutateHeaders` never see the HTTPS traffic to
     * these hosts; plain-HTTP proxy requests to them are unaffected (those
     * are readable without termination and keep the normal request pipeline).
     *
     * Absent, or returning true, means today's behaviour: terminate.
     */
    shouldTerminateTLS?(hostname: string, port: number): boolean;
    /**
     * Per-request filter; runs on plain-HTTP proxy requests and on terminated
     * HTTPS requests. See request-filter.ts.
     */
    filterRequest?: FilterRequestCallback;
    /**
     * Mutate forwarded headers on the TLS-terminated path, after the allow
     * decision and before the upstream request is built. The upstream leg is
     * always cert-verified (rejectUnauthorized defaults to true), so the TLS
     * handshake fails before any mutated header bytes reach an unverified
     * server. See {@link MutateForwardedHeaders}.
     */
    mutateHeaders?: MutateForwardedHeaders;
    /**
     * Mutate forwarded headers on the plain-HTTP path. Separate from
     * `mutateHeaders` so callers can wire the TLS path only — credential
     * injection over plaintext is opt-in.
     */
    mutateHeadersPlaintext?: MutateForwardedHeaders;
    /**
     * Per-destination sentinel→real byte pairs for masked-credential
     * substitution in request BODIES on the TLS-terminated path — the body
     * counterpart of `mutateHeaders`. Consulted once per body-carrying
     * request; an empty/undefined result keeps the existing bare body pipe,
     * byte-identical. See body-substitution.ts for gating and framing rules.
     */
    getBodySubstitutions?: GetBodySubstitutions;
    /**
     * Body substitution on the plain-HTTP path. Separate from
     * `getBodySubstitutions` for the same reason `mutateHeadersPlaintext` is
     * separate: credential injection over plaintext is opt-in.
     */
    getBodySubstitutionsPlaintext?: GetBodySubstitutions;
    /**
     * Per-request AWS SigV4 hook on the TLS-terminated path. Runs in
     * forwardUpstream around `mutateHeaders`: requests whose signature
     * references a masked credential pair are re-signed with the real
     * credentials (or denied per policy for shapes that cannot be
     * re-signed); everything else is untouched. See credential-aws-pairs.ts.
     */
    planSigv4?: PlanSigv4;
    /**
     * Override for the SigV4 literal-hash body buffering cap
     * (MAX_SIGV4_RESIGN_BODY_BYTES). Primarily a test seam — exercising the
     * over-cap denial with the production 64 MiB value would need a 64 MiB
     * fixture upload per test.
     */
    maxSigv4ResignBodyBytes?: number;
    /**
     * Additional trusted CA(s) for the terminating proxy's outbound TLS leg.
     * Unset → system roots + NODE_EXTRA_CA_CERTS. Primarily a test seam.
     */
    tlsTerminateUpstreamCA?: string | Buffer | Array<string | Buffer>;
    /**
     * Optional upstream HTTP proxy. When present, direct-connect traffic (i.e.
     * not routed via mitmProxy) is tunnelled through this parent instead of
     * connecting directly. NO_PROXY-matched hosts still connect directly.
     */
    parentProxy?: ResolvedParentProxy;
    /**
     * Per-session bearer token. When set, every CONNECT and absolute-URI
     * request must carry `Proxy-Authorization: Basic base64("srt:<token>")`
     * or it gets a 407. Without this, any host process can dial 127.0.0.1
     * and reach the filter callback.
     */
    proxyAuthToken?: string;
}
export declare function createHttpProxyServer(options: HttpProxyServerOptions): Server;
//# sourceMappingURL=http-proxy.d.ts.map