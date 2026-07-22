/**
 * Decoding support for encoded credential formats (`decode` on a
 * `credentials.files` entry). Currently JWT only.
 *
 * Pure helpers: the default extraction pattern for finding JWT candidates
 * in a file, the verification predicate that confirms a candidate actually
 * is a JWT before it gets masked, and the minting of a JWT-shaped fake to
 * stand in for the real token inside the sandbox.
 */
/**
 * Default `extract` pattern for `decode: "jwt"` entries.
 *
 * A JWT's first segment is the base64url encoding of a JSON header that
 * starts `{"` (it always declares `alg`/`typ`), and base64url of `{"` is
 * `eyJ` — so every JWT starts with `eyJ`. Capture group 1 is the whole
 * three-segment token. The pattern over-matches (any eyJ-prefixed
 * base64url triple); {@link verifyJwt} filters the false positives.
 */
export declare const JWT_DEFAULT_EXTRACT_PATTERN = "(eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)";
/**
 * True when `candidate` is structurally a JWT: three dot-separated
 * segments, the first two base64url-decoding to JSON, and the header
 * (segment 1) declaring an `alg` property.
 *
 * Used to filter extraction candidates before masking — a regex match
 * that fails this check (e.g. a random base64 blob the default pattern
 * over-matched) is left untouched rather than masked.
 */
export declare function verifyJwt(candidate: string): boolean;
/**
 * Mint a structurally valid fake JWT carrying the sentinel identity
 * `fake_value_<uuid>` in its `sub` claim. Deterministic given `uuid`.
 *
 * The fake is parseable by client-side JWT handling (three segments, JSON
 * header/payload, far-future `exp`), so a tool inside the sandbox that
 * inspects the token before sending it doesn't break. The header says
 * `alg: HS256` — NOT `alg: none` — deliberately: misconfigured validators
 * accept `alg: none` tokens as valid, whereas an HS256 header forces every
 * validator to attempt signature verification and reject the garbage
 * signature. So if the fake ever reaches a verifier unswapped (e.g. sent
 * to a non-injectHosts destination, the designed fail-closed pass-through),
 * it is cryptographically rejected.
 */
export declare function mintFakeJwt(uuid: string): string;
/** Result of {@link maskJwtClaims}. */
export interface MaskedClaimsResult {
    /**
     * The rebuilt token: the original header segment verbatim, the modified
     * payload re-encoded, and the fixed filler signature.
     */
    fakeToken: string;
    /** Claim name → the sentinel now carried in the fake payload. */
    claimSentinels: Map<string, string>;
}
/**
 * Claim-level masking for a verified JWT: replace each named top-level
 * payload claim that is present with a string value by a caller-provided
 * sentinel, and rebuild the token around the modified payload.
 *
 * The rebuilt token is `header.payload'.signature-filler`:
 *
 * - **Header**: the original base64url segment is reused verbatim, so the
 *   token still advertises the real `alg`/`typ`/`kid` and client-side
 *   header inspection sees exactly what it would outside the sandbox.
 * - **Payload**: the decoded object with the named claims swapped for
 *   sentinels, re-encoded with `JSON.stringify`. Key order and whitespace
 *   inside the payload segment may differ from the original encoding —
 *   irrelevant to any JSON consumer, and the segment bytes change anyway
 *   because a claim value changed.
 * - **Signature**: the fixed filler from {@link mintFakeJwt}, NOT the real
 *   signature. For RS/ES algorithms signature verification needs only the
 *   public key, so shipping the real signature over a modified payload
 *   would hand the sandbox an offline brute-force oracle for a low-entropy
 *   masked claim (guess the claim, re-encode, verify). The filler also
 *   keeps the fake a non-credential end to end, consistent with the
 *   garbage-signature rationale in {@link mintFakeJwt}.
 *
 * Claims that are absent from the payload, or present with a non-string
 * value, are skipped (the caller logs them). Returns `null` — without
 * invoking `sentinelFor` — when no named claim matched, or when the
 * payload does not decode to a JSON object; the caller routes that
 * through its no-match policy.
 *
 * Pure on `token`/`claims`; the callback may close over a registry.
 */
export declare function maskJwtClaims(token: string, claims: readonly string[], sentinelFor: (claim: string, realValue: string) => string): MaskedClaimsResult | null;
//# sourceMappingURL=credential-decode.d.ts.map