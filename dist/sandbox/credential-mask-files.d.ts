/**
 * Credential file masking (Linux).
 *
 * For a `credentials.files` entry with `mode: "mask"`, srt reads the real
 * file content on the host, registers one or more sentinels in the
 * {@link SentinelRegistry}, and writes a fake file (sentinel-substituted)
 * to a manager-owned temp directory. The Linux sandbox then `--ro-bind`s
 * the fake over the real path, so the sandboxed process reads the
 * sentinel(s). The proxy substitution from env-var masking already scans
 * every header for any registered sentinel, so a tool that does
 * `Authorization: Bearer $(cat <maskedFile>)` reaches the upstream with
 * the real bytes — no proxy changes required.
 *
 * Without `extract`, masking is **whole-file**: one sentinel replaces the
 * entire content. With `extract`, masking is **structured**: a regex picks
 * out the credential value(s) and only those spans are replaced, so a tool
 * that parses the file (JSON/YAML/.netrc) still sees valid syntax. See
 * {@link extractAndSubstitute} and {@link CredentialFileConfigSchema}.
 *
 * On macOS, SBPL cannot redirect reads, so masked files degrade to
 * `mode: "deny"` (see macos-sandbox-utils.ts).
 */
import type { CredentialFileConfig } from './sandbox-config.js';
import type { SentinelRegistry } from './credential-sentinel.js';
/** One masked file's bind mapping for the platform builder. */
export interface MaskedFileBind {
    /** Resolved (tilde-expanded, realpath'd) host path of the real file. */
    realPath: string;
    /** Path to the fake file containing the sentinel. */
    fakePath: string;
}
/**
 * Manager-owned temp dir holding the fake files.
 *
 * INVARIANT: this directory must never be writable from inside the sandbox.
 * The Linux layer enforces this by emitting `--ro-bind <dirPath> <dirPath>`
 * after every other filesystem mount (see generateFilesystemArgs), so the
 * store stays read-only even if a caller's allowWrite covers os.tmpdir() or
 * the host's $TMPDIR points under a default-writable path. If the sandbox
 * could write here it could replace a fake's content (the bind exposes the
 * source file) or plant a symlink for a later host-side write() to follow.
 */
export declare class MaskedFileStore {
    private dir;
    private readonly byKey;
    /**
     * Write `sentinel` to a fake file for `key` and return its path.
     * Idempotent on `key`: a repeat call rewrites the same fake (so a
     * changed sentinel after re-register propagates) instead of leaking a
     * new file per wrapWithSandbox() call.
     */
    write(key: string, sentinel: string): string;
    /** Remove the temp dir and every fake file in it. Idempotent. */
    dispose(): void;
    /** Temp dir path, or undefined if no fake has been written yet. */
    get dirPath(): string | undefined;
}
/** Result of {@link buildMaskedFileBinds}. */
export interface MaskedFileBuildResult {
    binds: MaskedFileBind[];
    /**
     * Resolved paths of `mode: "mask"` entries that degraded to deny at
     * runtime — populated when `extract` matches nothing (or, with
     * `decode`, no candidate verifies) and the entry's `onExtractNoMatch`
     * is `"deny"`. Callers union these into the read-deny set so the
     * credential file is unreadable rather than exposed.
     */
    degradeToDenyPaths: string[];
}
/**
 * For each `mode: "mask"` file entry: resolve the path, read the real
 * content, build the fake content (whole-file or structured per `extract`),
 * register sentinels in `registry`, write the fake via `store`, and return
 * the bind list plus any entries that degraded to deny.
 *
 * Whole-file mode (no `extract`): one sentinel keyed `file:<path>` whose
 * real value is the entire file content; the fake file *is* the sentinel.
 *
 * Structured mode (`extract` and/or `decode` set): one sentinel per
 * distinct captured value, keyed `file:<path>#<i>`; the fake file is the
 * real content with each captured span replaced by its sentinel. With
 * `decode: "jwt"`, candidates come from the explicit `extract` pattern or
 * the built-in JWT pattern, each candidate must pass {@link verifyJwt}
 * before it is masked (failed candidates are left untouched), and the
 * sentinel is a JWT-shaped fake ({@link mintFakeJwt}) registered via
 * `registerWithSentinel`. With `maskClaims`, masking goes one level
 * deeper: each named top-level payload claim present with a string value
 * gets its own sentinel and the token is rebuilt around the modified
 * payload ({@link maskJwtClaims}); BOTH mappings are registered — the
 * whole fake token → the whole real token (a tool sending the token as a
 * bearer credential) and each claim sentinel → the real claim value (a
 * tool extracting the claim and sending it alone) — under the same
 * injectHosts. Named claims absent or non-string in a token are skipped
 * with a debug log (portable-config posture, like a missing file). If the
 * regex matches nothing — or, with decode, no candidate verifies, or with
 * `maskClaims`, no named claim matches in any verified token — the
 * entry's `onExtractNoMatch` decides:
 * - `"warn"` (default): skip the entry with a loud stderr warning —
 *   fail-open, the file stays readable via the root mount;
 * - `"deny"`: push the path to `degradeToDenyPaths` — fail-closed, the
 *   file becomes unreadable inside the sandbox;
 * - `"error"`: throw, so nothing runs until the config is fixed.
 * With `maskDuplicates`, verbatim occurrences of each captured value
 * outside the matched spans are also replaced (see {@link ExtractOptions}).
 * Composed with `decode`, the duplicate pass covers only captures that
 * passed verification — a duplicate is the same value, so it inherits the
 * verified capture's sentinel without re-verification; unverified
 * candidates (left untouched by the decode gate) never mask duplicates.
 *
 * Entries whose path does not exist, is unreadable, or resolves to a
 * directory are skipped with a debug log — same posture as a masked env
 * var that's unset on the host: nothing to protect, and surfacing a hard
 * error would make a portable config brittle across machines.
 *
 * The directory check is the authoritative one (the schema only catches a
 * trailing slash); whole-file masking has no meaning for a directory.
 */
export declare function buildMaskedFileBinds(files: readonly CredentialFileConfig[], allowedDomains: readonly string[], registry: SentinelRegistry, store: MaskedFileStore): MaskedFileBuildResult;
export declare const MASKED_FILE_STORE_PREFIX = "srt-credmask-";
//# sourceMappingURL=credential-mask-files.d.ts.map