/**
 * Credential env-var masking.
 *
 * For a `credentials.envVars` entry with `mode: "mask"`, srt reads the real
 * value from the host environment, registers one or more sentinels in the
 * {@link SentinelRegistry}, and sets the variable to the fake value inside
 * the sandbox (bwrap `--setenv` on Linux, the env preamble on macOS). The
 * proxy substitutes sentinel→real on egress to the entry's injectHosts.
 *
 * Without `extract`, masking is **whole-value**: one sentinel replaces the
 * entire value. With `extract`, masking is **structured**: a regex picks
 * out the credential span(s) and only those are replaced, so a tool that
 * parses the value (e.g. a `DATABASE_URL` connection string) still sees
 * valid syntax. See {@link extractAndSubstitute} and
 * {@link CredentialEnvVarConfigSchema}.
 */
import type { CredentialEnvVarConfig } from './sandbox-config.js';
import type { SentinelRegistry } from './credential-sentinel.js';
/** Result of {@link buildMaskedEnvVars}. */
export interface MaskedEnvBuildResult {
    /** NAME → fake value to set inside the sandbox. */
    setEnvVars: Record<string, string>;
    /**
     * Names of `mode: "mask"` entries that degraded to unset at runtime —
     * populated when `extract` matches nothing and the entry's
     * `onExtractNoMatch` is `"deny"`. Callers union these into the
     * unset-env set so the credential value is withheld rather than
     * exposed (the env analog of a file degrading to `mode: "deny"`).
     */
    degradeToUnsetNames: string[];
}
/**
 * For each `mode: "mask"` env-var entry: read the real value from `env`,
 * build the fake value (whole-value or structured per `extract`), register
 * sentinels in `registry`, and return the set-env map plus any entries
 * that degraded to unset.
 *
 * Whole-value mode (no `extract`): one sentinel keyed on the bare variable
 * name whose real value is the entire env value; the fake value *is* the
 * sentinel.
 *
 * Structured mode (`extract` set): one sentinel per distinct captured
 * value, keyed `env:<NAME>#<i>`; the fake value is the real value with
 * each captured span replaced by its sentinel. If the regex matches
 * nothing, the entry's `onExtractNoMatch` decides:
 * - `"warn"` (default): skip the entry with a loud stderr warning —
 *   fail-open, the variable passes through with its real value;
 * - `"deny"`: push the name to `degradeToUnsetNames` — fail-closed, the
 *   variable is unset inside the sandbox;
 * - `"error"`: throw, so nothing runs until the regex is fixed.
 *
 * Decoded mode (`decode: "jwt"`): the whole value is verified as a JWT
 * and replaced by a JWT-shaped fake registered as a caller-minted
 * sentinel; with `maskClaims`, each named top-level payload claim present
 * with a string value gets its own sentinel (keyed `env:<NAME>#<claim>`)
 * and the token is rebuilt around the modified payload — BOTH the whole
 * rebuilt token and each claim sentinel are registered under the same
 * injectHosts. A value that does not verify — or, with `maskClaims`,
 * verifies but has no named claim present as a string — fails open with a
 * loud stderr warning.
 *
 * A masked variable with no value in `env` is skipped — there is nothing
 * to protect, and emitting an unset (or set) var would change tool
 * behaviour (presence checks would flip).
 *
 * `mode: "deny"` entries are ignored here; the caller handles them
 * directly (they need no registry or host environment access).
 */
export declare function buildMaskedEnvVars(envVars: readonly CredentialEnvVarConfig[], allowedDomains: readonly string[], registry: SentinelRegistry, env?: Record<string, string | undefined>): MaskedEnvBuildResult;
//# sourceMappingURL=credential-mask-env.d.ts.map