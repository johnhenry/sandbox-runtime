/**
 * MITM CA loader/generator for the in-process TLS-terminating proxy.
 *
 * The CA is supplied via `network.tlsTerminate.{caCertPath,caKeyPath}` (see
 * sandbox-config.ts). If both paths are omitted, SRT generates an ephemeral
 * RSA-2048 self-signed CA into a temp directory; the cert path is what the
 * trust env vars point at. The caller is responsible for cleaning up via
 * `disposeMitmCA()` (SandboxManager.reset() does this).
 */
import forge from 'node-forge';
import { type SecureContext } from 'node:tls';
import type { LeafCert } from './mitm-leaf.js';
export type MitmCA = {
    certPath: string;
    keyPath: string;
    /**
     * PEM bundle the sandboxed child's trust env vars point at: this CA
     * followed by the host's regular roots (Node's bundled Mozilla store plus
     * the parent's NODE_EXTRA_CA_CERTS, if any) and any configured
     * tlsTerminate.extraCaCertPaths. Most of the per-tool vars
     * (SSL_CERT_FILE, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE, ...) REPLACE the
     * tool's trust store rather than extend it, so pointing them at the CA
     * alone would leave the child unable to verify any real certificate —
     * which matters for connections SRT does not terminate
     * (tlsTerminate.excludeDomains). Always lives in an SRT-owned temp dir.
     */
    trustBundlePath: string;
    certPem: string;
    keyPem: string;
    /** Parsed CA certificate (issuer for minted leaf certs). */
    cert: forge.pki.Certificate;
    /** Parsed CA private key. RSA only. */
    key: forge.pki.rsa.PrivateKey;
    /** Per-hostname cache of leaf certs minted against this CA. */
    leafCerts: Map<string, LeafCert>;
    /** Per-hostname cache of TLS SecureContexts wrapping the leaf certs. */
    secureContexts: Map<string, SecureContext>;
    /**
     * DER-encoded empty CRL signed by this CA. Schannel (Windows System32
     * curl, git's default backend, cargo) checks revocation on every leaf and
     * hard-fails when a CRL Distribution Point can't be reached — see
     * `crlUrl`. Serving this at that URL turns "revocation unknown" into
     * "checked; not revoked" without a per-tool `--ssl-no-revoke` /
     * `schannelCheckRevoke=false` / `CARGO_HTTP_CHECK_REVOKE=false`.
     */
    crlDer: Buffer;
    /**
     * URL every minted leaf's `cRLDistributionPoints` extension points at
     * (`http://127.0.0.1:<proxyPort>/srt.crl`). Set by sandbox-manager on
     * Windows once the local mux port is bound; the proxy answers a plain
     * GET on that path with `crlDer`. Left unset on Linux/macOS (child sees
     * the proxy at a different port under bwrap --unshare-net, so a
     * host-namespace URL would be unreachable) and when the HTTP proxy is
     * external — in both cases leaves carry no CDP, i.e. pre-CRL behaviour.
     */
    crlUrl?: string;
    /**
     * True when SRT generated this CA into a temp directory. disposeMitmCA()
     * removes that directory; user-supplied CAs are left alone.
     */
    ephemeral: boolean;
};
/** Origin-form path the HTTP proxy answers with `crlDer`. */
export declare const CRL_PATH = "/srt.crl";
/**
 * Return the CA's Subject Key Identifier as raw bytes for use as an
 * authorityKeyIdentifier.keyIdentifier (leaf certs and the CRL both need it).
 *
 * node-forge stores a cert's subjectKeyIdentifier extension value as a *hex
 * string* (both for in-memory certs and certs parsed from PEM), but expects
 * AKI's keyIdentifier as *raw bytes* — passing the hex through verbatim
 * encodes the ASCII hex chars as the key id and the chain fails to verify.
 * If the CA has no SKI extension (e.g. a v1 user-supplied CA), derive the
 * RFC 5280 method-1 value from its public key.
 */
export declare function caSubjectKeyId(caCert: forge.pki.Certificate): string;
/**
 * Drop-in replacement for `cert.sign(key, md.sha256.create())` that computes
 * the RSASSA-PKCS1-v1_5 / SHA-256 signature via Node's native `crypto.sign()`
 * instead of node-forge's pure-JS RSA.
 *
 * node-forge routes RSA *keypair generation* to native `crypto` when available,
 * but its `PrivateKey.sign()` is always pure JS: jsbn `BigInteger.modPow`
 * (~3000 Montgomery squarings for a 2048-bit modulus). On a JIT engine that's
 * ~50–70 ms per signature; on an interpreter or baseline-only tier it can be
 * an order of magnitude worse — and `generateEphemeralCA()` runs on the cold
 * path of every process that constructs a SandboxManager. Native
 * `crypto.sign()` is ~1–2 ms and, because RSASSA-PKCS1-v1_5 is deterministic,
 * produces byte-identical output. See test/sandbox/mitm-ca.test.ts for the
 * byte-for-byte equivalence check.
 */
export declare function signCertificateNative(cert: forge.pki.Certificate, keyPem: string): void;
/**
 * RSASSA-PKCS1-v1_5 / SHA-256 sign of a forge binary-string `der` with the
 * PEM-encoded RSA private key `keyPem`, returning the signature as a forge
 * binary string. Native equivalent of `forgeKey.sign(sha256Digest)`.
 */
export declare function rsaSha256SignNative(der: string, keyPem: string): string;
/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export declare function createMitmCA(opts: {
    caCertPath?: string;
    caKeyPath?: string;
    /** PEM CA files appended to the trust bundle; unreadable paths skipped. */
    extraCaCertPaths?: string[];
}): MitmCA;
/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir too when SRT generated the CA (for an
 * ephemeral CA they are the same directory). User-supplied CA files are
 * left alone.
 */
export declare function disposeMitmCA(ca: MitmCA): Promise<void>;
/**
 * Build a DER-encoded X.509 v2 CRL, signed by `key`, listing zero revoked
 * certificates. `nextUpdate` is the CA's `notAfter` (or now+1d if the CA is
 * already expired) so a single per-session CRL stays fresh for the CA's
 * lifetime.
 *
 * node-forge has no CRL builder, so this hand-assembles the RFC 5280 §5.1
 * `CertificateList` from asn1 primitives — the same approach the library
 * uses internally for certificates. Carries the two extensions RFC 5280
 * §5.2 says conforming issuers MUST include: `authorityKeyIdentifier`
 * (matching the CA's SKI) and `cRLNumber`.
 */
export declare function generateEmptyCrl(cert: forge.pki.Certificate, keyPem: string): Buffer;
export declare function randomSerial(): string;
export declare function daysFromNow(days: number): Date;
//# sourceMappingURL=mitm-ca.d.ts.map