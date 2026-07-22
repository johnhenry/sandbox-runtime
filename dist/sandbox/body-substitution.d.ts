/**
 * Streaming sentinel→real substitution for forwarded HTTP request bodies.
 *
 * The proxy substitutes masked-credential sentinels in request headers
 * (SentinelRegistry.substituteInHeaders); a credential a tool places in a
 * request body (JSON payload, form post) would otherwise reach the API as
 * the useless fake. Sentinels are exact-match strings over `[a-z0-9_-]`, so
 * they survive JSON, form-urlencoded, multipart, and XML verbatim — a raw
 * byte scan needs no format parsing. Bodies are never buffered whole:
 * memory is bounded by one chunk plus a hold-back of `maxSentinelLength - 1`
 * bytes carried across chunk boundaries.
 *
 * Fail-safe direction: substitution is fake→real, so a missed sentinel
 * (compressed body, base64-wrapped, split by an encoder) means the FAKE
 * value reaches the API and auth fails — never a leaked secret.
 */
import type { IncomingHttpHeaders, IncomingMessage } from 'node:http';
import { Transform } from 'node:stream';
/** One sentinel→real replacement, as raw bytes. */
export interface SentinelBufferPair {
    sentinel: Buffer;
    realValue: Buffer;
}
/**
 * Per-destination substitution set for masked-credential body rewriting.
 * Consulted once per request with the canonical destination host (the
 * CONNECT target, never the spoofable Host header). Empty/undefined means
 * no credential is injectable at the host — the caller must keep the
 * existing bare pipe, byte-identical.
 */
export type GetBodySubstitutions = (destHost: string) => SentinelBufferPair[] | undefined;
/** True when substitution cannot change the body length. */
export declare function allLengthMatched(pairs: readonly SentinelBufferPair[]): boolean;
/**
 * Build the substitution Transform for one forwarded request, or undefined
 * when the body must keep the existing bare pipe, byte-identical: bodyless
 * method, no credential injectable at `destHost`, or a Content-Encoding the
 * byte scan cannot see through.
 *
 * When substitution can change the body length (some injectable sentinel is
 * not length-matched with its real value — e.g. a caller-minted JWT-shaped
 * fake), Content-Length is deleted from `fwdHeaders` so the outbound
 * request re-frames as chunked; otherwise Content-Length stays verbatim.
 */
export declare function prepareBodySubstitution(getBodySubstitutions: GetBodySubstitutions | undefined, req: IncomingMessage, fwdHeaders: IncomingHttpHeaders, destHost: string): Transform | undefined;
/**
 * Transform that replaces every occurrence of each pair's sentinel bytes
 * with its real-value bytes.
 *
 * Boundary-safe: the last `maxSentinelLength - 1` bytes of each chunk are
 * held back and prepended to the next chunk, so a sentinel split across any
 * chunk boundary is still seen whole; the hold-back is flushed on stream
 * end. Replacement is left-to-right, resuming after each replacement — the
 * substituted real value is never rescanned. Backpressure propagates
 * through normal Transform semantics.
 */
export declare function createBodySubstitutionTransform(pairs: readonly SentinelBufferPair[]): Transform;
//# sourceMappingURL=body-substitution.d.ts.map