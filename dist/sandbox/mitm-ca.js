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
import { sign as cryptoSign } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { rootCertificates } from 'node:tls';
import { logForDebugging } from '../utils/debug.js';
const { asn1, pki, md, random, util } = forge;
// node-forge exports pki.getTBSCertificate at runtime; @types/node-forge omits it.
const getTBSCertificate = pki.getTBSCertificate;
/**
 * Matches one PEM CERTIFICATE block. Used to extract just the certificates
 * out of files listed in tlsTerminate.extraCaCertPaths before they are
 * copied into the (world-readable) trust bundle.
 */
const PEM_CERT_BLOCK = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
/** Origin-form path the HTTP proxy answers with `crlDer`. */
export const CRL_PATH = '/srt.crl';
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
export function caSubjectKeyId(caCert) {
    const ext = caCert.getExtension('subjectKeyIdentifier');
    return ext?.subjectKeyIdentifier
        ? util.hexToBytes(ext.subjectKeyIdentifier)
        : caCert.generateSubjectKeyIdentifier().getBytes();
}
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
export function signCertificateNative(cert, keyPem) {
    const oid = pki.oids.sha256WithRSAEncryption;
    cert.siginfo.algorithmOid = oid;
    cert.signatureOid = oid;
    cert.tbsCertificate = getTBSCertificate(cert);
    const tbsDer = asn1.toDer(cert.tbsCertificate).getBytes();
    cert.signature = rsaSha256SignNative(tbsDer, keyPem);
    // Match cert.sign()'s side effect so callers that read cert.md see the same
    // populated digest a forge-signed cert would carry.
    cert.md = md.sha256.create();
    cert.md.update(tbsDer);
}
/**
 * RSASSA-PKCS1-v1_5 / SHA-256 sign of a forge binary-string `der` with the
 * PEM-encoded RSA private key `keyPem`, returning the signature as a forge
 * binary string. Native equivalent of `forgeKey.sign(sha256Digest)`.
 */
export function rsaSha256SignNative(der, keyPem) {
    return cryptoSign('sha256', Buffer.from(der, 'binary'), keyPem).toString('binary');
}
/**
 * Create a MitmCA. If `caCertPath`/`caKeyPath` are provided, load from disk
 * (throws if either file is missing, unreadable, not PEM, fails to parse, or
 * the key is not RSA). If both are omitted, generate an ephemeral CA into a
 * fresh temp directory.
 *
 * Pure factory: no module-level state. The caller (SandboxManager) owns the
 * returned object and its lifetime.
 */
export function createMitmCA(opts) {
    if (opts.caCertPath && opts.caKeyPath) {
        return loadCA(opts.caCertPath, opts.caKeyPath, opts.extraCaCertPaths);
    }
    if (opts.caCertPath || opts.caKeyPath) {
        throw new Error('tlsTerminate: caCertPath and caKeyPath must be provided together');
    }
    return generateEphemeralCA(opts.extraCaCertPaths);
}
/**
 * Remove the SRT-owned temp directories for this CA: the trust-bundle dir
 * always, and the cert/key dir too when SRT generated the CA (for an
 * ephemeral CA they are the same directory). User-supplied CA files are
 * left alone.
 */
export async function disposeMitmCA(ca) {
    const dirs = new Set([dirname(ca.trustBundlePath)]);
    if (ca.ephemeral)
        dirs.add(dirname(ca.certPath));
    for (const dir of dirs) {
        try {
            await rm(dir, { recursive: true, force: true });
        }
        catch (err) {
            logForDebugging(`[mitm-ca] cleanup failed: ${err.message}`, {
                level: 'warn',
            });
        }
    }
}
/**
 * Write the child-facing trust bundle into `dir` and return its path: the
 * MITM CA first, then the roots the host would normally trust, so HTTPS
 * clients in the sandbox accept proxy-minted leaves AND can still verify the
 * real certificate of any host SRT tunnels opaquely instead of terminating
 * (tlsTerminate.excludeDomains). Bundling Node's root store is best-effort
 * compatibility — a tool with its own CA file config is unaffected. Extra
 * roots from tlsTerminate.extraCaCertPaths go last, with the same append
 * semantics as NODE_EXTRA_CA_CERTS.
 */
function writeTrustBundle(dir, caCertPem, extraCaCertPaths) {
    const parts = [caCertPem.trim(), ...rootCertificates];
    // Honour extra roots the parent process trusts (e.g. a corporate CA).
    const extra = process.env.NODE_EXTRA_CA_CERTS;
    if (extra) {
        try {
            parts.push(readFileSync(extra, 'utf8').trim());
        }
        catch {
            // Missing/unreadable NODE_EXTRA_CA_CERTS: ignore, same as Node does.
        }
    }
    // Honour site-local roots from config (tlsTerminate.extraCaCertPaths),
    // e.g. an internal mTLS CA presented by excluded/passthrough hosts. Paths
    // may exist on only some hosts, so a missing file is skipped, not fatal —
    // but log it, or a typo'd path is undiagnosable.
    for (const extraPath of extraCaCertPaths ?? []) {
        let raw;
        try {
            raw = readFileSync(extraPath, 'utf8');
        }
        catch (err) {
            const code = err.code ?? String(err);
            logForDebugging(`[mitm-ca] extraCaCertPaths: cannot read ${extraPath} (${code}); ` +
                `skipping`, { level: 'warn' });
            continue;
        }
        // Append only the CERTIFICATE blocks. The bundle is world-readable
        // (0o644) and handed to the sandboxed child, so anything else the file
        // carries (e.g. the key of a combined cert+key PEM) must not be copied.
        const certs = raw.match(PEM_CERT_BLOCK);
        if (!certs) {
            logForDebugging(`[mitm-ca] extraCaCertPaths: ${extraPath} has no PEM CERTIFICATE ` +
                `block; skipping`, { level: 'warn' });
            continue;
        }
        parts.push(...certs);
    }
    const path = join(dir, 'trust-bundle.crt');
    writeFileSync(path, parts.join('\n') + '\n', { mode: 0o644 });
    return path;
}
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
export function generateEmptyCrl(cert, keyPem) {
    const SHA256_RSA = pki.oids.sha256WithRSAEncryption;
    const sigAlg = () => seq([
        asn1.create(C.UNIVERSAL, T.OID, false, asn1.oidToDer(SHA256_RSA).getBytes()),
        asn1.create(C.UNIVERSAL, T.NULL, false, ''),
    ]);
    // extnValue is the DER of the extension's own ASN.1, wrapped in an
    // OCTET STRING at the Extension level.
    const ext = (oid, value) => seq([
        asn1.create(C.UNIVERSAL, T.OID, false, asn1.oidToDer(oid).getBytes()),
        asn1.create(C.UNIVERSAL, T.OCTETSTRING, false, asn1.toDer(value).getBytes()),
    ]);
    const crlExtensions = asn1.create(C.CONTEXT_SPECIFIC, 0, true, [
        seq([
            // authorityKeyIdentifier ::= SEQUENCE { [0] KeyIdentifier }
            ext(pki.oids.authorityKeyIdentifier, seq([asn1.create(C.CONTEXT_SPECIFIC, 0, false, caSubjectKeyId(cert))])),
            // cRLNumber ::= INTEGER — one CRL per CA per session, so a fixed 1.
            ext('2.5.29.20', asn1.create(C.UNIVERSAL, T.INTEGER, false, '\x01')),
        ]),
    ]);
    const now = new Date();
    const caEnd = cert.validity.notAfter;
    const nextUpdate = caEnd > now ? caEnd : daysFromNow(1);
    const tbsCertList = seq([
        // version v2 == INTEGER 1 (required when crlExtensions is present)
        asn1.create(C.UNIVERSAL, T.INTEGER, false, '\x01'),
        sigAlg(),
        // Issuer Name: RFC 5280 §5.1.2.3 requires this match the CA subject
        // byte-for-byte. node-forge normalises DN attributes on parse (its
        // certificateFromPem re-encodes via distinguishedNameToAsn1 too, so the
        // "original" DER isn't recoverable via the library), which means a
        // user-supplied CA whose subject uses e.g. multi-valued RDNs or a
        // non-canonical string type could produce a differently-encoded issuer
        // here. Schannel matches on AKI keyid (present above) not issuer DN, and
        // the ephemeral CA is generated by the same encoder, so this holds in
        // practice; noted for completeness.
        pki.distinguishedNameToAsn1(cert.subject),
        asn1Time(now),
        asn1Time(nextUpdate),
        // revokedCertificates: OMITTED. RFC 5280: "When there are no revoked
        // certificates, the revoked certificates list MUST be absent."
        crlExtensions,
    ]);
    const sig = rsaSha256SignNative(asn1.toDer(tbsCertList).getBytes(), keyPem);
    const crl = seq([
        tbsCertList,
        sigAlg(),
        // BIT STRING: leading 0x00 = zero unused bits.
        asn1.create(C.UNIVERSAL, T.BITSTRING, false, '\x00' + sig),
    ]);
    return Buffer.from(asn1.toDer(crl).getBytes(), 'binary');
}
const C = asn1.Class;
const T = asn1.Type;
function seq(v) {
    return asn1.create(C.UNIVERSAL, T.SEQUENCE, true, v);
}
/** UTCTime for years <2050, GeneralizedTime otherwise (RFC 5280 §4.1.2.5). */
function asn1Time(d) {
    return d.getUTCFullYear() < 2050
        ? asn1.create(C.UNIVERSAL, T.UTCTIME, false, asn1.dateToUtcTime(d))
        : asn1.create(C.UNIVERSAL, T.GENERALIZEDTIME, false, asn1.dateToGeneralizedTime(d));
}
function loadCA(certPath, keyPath, extraCaCertPaths) {
    const certPem = readPem(certPath, 'CERTIFICATE', 'tlsTerminate.caCertPath');
    const keyPem = readPem(keyPath, 'PRIVATE KEY', 'tlsTerminate.caKeyPath');
    let cert;
    let key;
    try {
        cert = pki.certificateFromPem(certPem);
        key = pki.privateKeyFromPem(keyPem);
    }
    catch (err) {
        throw new Error(`tlsTerminate: failed to parse CA from ${certPath}: ` +
            err.message);
    }
    if (!('n' in key) || !('d' in key)) {
        // node-forge can only sign with RSA private keys.
        throw new Error(`tlsTerminate.caKeyPath: CA key at ${keyPath} must be RSA`);
    }
    // The CA files are the user's; the trust bundle still needs an SRT-owned
    // directory of its own.
    const bundleDir = mkdtempSync(join(tmpdir(), 'srt-ca-'));
    const trustBundlePath = writeTrustBundle(bundleDir, certPem, extraCaCertPaths);
    logForDebugging(`[mitm-ca] loaded CA from ${certPath}`);
    return {
        certPath,
        keyPath,
        trustBundlePath,
        certPem,
        keyPem,
        cert,
        key: key,
        leafCerts: new Map(),
        secureContexts: new Map(),
        crlDer: generateEmptyCrl(cert, keyPem),
        ephemeral: false,
    };
}
function generateEphemeralCA(extraCaCertPaths) {
    const keys = pki.rsa.generateKeyPair(2048);
    const cert = pki.createCertificate();
    cert.publicKey = keys.publicKey;
    cert.serialNumber = randomSerial();
    cert.validity.notBefore = daysFromNow(-1);
    cert.validity.notAfter = daysFromNow(825);
    const subject = [
        { name: 'commonName', value: 'sandbox-runtime ephemeral CA' },
        { name: 'organizationName', value: 'sandbox-runtime' },
    ];
    cert.setSubject(subject);
    cert.setIssuer(subject);
    cert.setExtensions([
        { name: 'basicConstraints', cA: true, critical: true },
        {
            name: 'keyUsage',
            critical: true,
            keyCertSign: true,
            cRLSign: true,
            digitalSignature: true,
        },
        { name: 'subjectKeyIdentifier' },
    ]);
    const keyPem = pki.privateKeyToPem(keys.privateKey);
    signCertificateNative(cert, keyPem);
    const certPem = pki.certificateToPem(cert);
    // Write to disk so trust env vars (NODE_EXTRA_CA_CERTS etc.) can point at
    // a real path. mkdtemp gives us an unguessable per-process directory.
    const dir = mkdtempSync(join(tmpdir(), 'srt-ca-'));
    const certPath = join(dir, 'ca.crt');
    const keyPath = join(dir, 'ca.key');
    writeFileSync(certPath, certPem, { mode: 0o644 });
    writeFileSync(keyPath, keyPem, { mode: 0o600 });
    const trustBundlePath = writeTrustBundle(dir, certPem, extraCaCertPaths);
    logForDebugging(`[mitm-ca] generated ephemeral CA at ${certPath}`);
    return {
        certPath,
        keyPath,
        trustBundlePath,
        certPem,
        keyPem,
        cert,
        key: keys.privateKey,
        leafCerts: new Map(),
        secureContexts: new Map(),
        crlDer: generateEmptyCrl(cert, keyPem),
        ephemeral: true,
    };
}
function readPem(path, label, field) {
    let pem;
    try {
        pem = readFileSync(path, 'utf8');
    }
    catch (err) {
        const code = err.code ?? String(err);
        throw new Error(`${field}: cannot read ${path} (${code})`);
    }
    // Accept either the exact label or a prefixed variant (e.g. "RSA PRIVATE KEY",
    // "EC PRIVATE KEY") for the key case.
    if (!new RegExp(`-----BEGIN [A-Z ]*${label}-----`).test(pem)) {
        throw new Error(`${field}: ${path} is not a PEM ${label}`);
    }
    return pem;
}
export function randomSerial() {
    // 16 random bytes, high bit cleared so the DER INTEGER stays positive.
    const bytes = random.getBytesSync(16);
    const hex = util.bytesToHex(bytes);
    const firstNibble = parseInt(hex[0], 16) & 0x7;
    return firstNibble.toString(16) + hex.slice(1);
}
export function daysFromNow(days) {
    const d = new Date();
    d.setDate(d.getDate() + days);
    return d;
}
//# sourceMappingURL=mitm-ca.js.map