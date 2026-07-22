/**
 * Structured credential extraction, shared by file masking
 * (credential-mask-files.ts) and env-var masking (credential-mask-env.ts).
 *
 * `extract` is a regex whose capture group 1 picks the credential value(s)
 * out of a larger text (a config file, a connection-string env var). Only
 * the captured span(s) are replaced with sentinels; the rest of the text is
 * preserved byte-for-byte so parsers still succeed inside the sandbox.
 */
/**
 * Result of {@link extractAndSubstitute}: the content with each matched
 * capture-group-1 span replaced by `sentinelFor(capture, i)`, plus the
 * distinct captured values in first-seen (index) order.
 */
export interface ExtractResult {
    fakeContent: string;
    captures: string[];
}
/** Options for {@link extractAndSubstitute}. */
export interface ExtractOptions {
    /**
     * If true, verbatim occurrences of each captured value *outside* the
     * regex-matched spans are also replaced with that capture's sentinel —
     * for a secret repeated where the regex does not reach (e.g. pasted
     * into a comment). The scan matches raw substrings: a short or common
     * captured value may corrupt unrelated content that happens to contain
     * it, so this option is intended for long, high-entropy secrets.
     */
    maskDuplicates?: boolean;
}
/**
 * Apply `pattern` globally to `content` and return `content` with each
 * matched capture-group-1 span replaced by `sentinelFor(capture, i)`,
 * where `i` is the zero-based index of the distinct captured value in
 * first-seen order.
 *
 * Offset-based: the regex `d` flag exposes capture-group offsets, so the
 * output is built by slicing between spans and splicing the sentinel in
 * at the exact `[start, end)` of group 1. By default only the
 * regex-matched span is replaced — a captured value that coincidentally
 * appears elsewhere in the content (outside any match) is left intact. No
 * placeholder pass, no substring-ordering concern.
 *
 * With `maskDuplicates` (see {@link ExtractOptions}), an indexOf scan
 * additionally collects every verbatim occurrence of each captured value
 * elsewhere in the content. All spans are computed against the ORIGINAL
 * content — never the partially substituted output — so an inserted
 * sentinel can never be re-matched and corrupted, even when a captured
 * value is a substring of the sentinel literal. Regex-match spans win
 * over verbatim ones, and verbatim scans run longest-capture-first so a
 * shorter capture that is a substring of a longer one cannot claim part
 * of the longer secret's occurrence. A capture the callback declined to
 * mask (returned unchanged — the decode-verification gate) is excluded
 * from the verbatim scan.
 *
 * Returns `null` when the pattern matches nothing — the caller routes
 * that per the entry's `onExtractNoMatch` option (warn / deny / error).
 *
 * Throws when a match has no group-1 capture. The schema already rejects
 * patterns with zero groups, so this only fires when group 1 is optional
 * and absent for some match (e.g. `"token: (\\S+)?"`); accepting that
 * would silently mask nothing for that occurrence.
 *
 * Pure on `content`/`pattern`; the callback may close over a registry.
 */
export declare function extractAndSubstitute(content: string, pattern: string, sentinelFor: (capture: string, index: number) => string, options?: ExtractOptions): ExtractResult | null;
//# sourceMappingURL=credential-extract.d.ts.map