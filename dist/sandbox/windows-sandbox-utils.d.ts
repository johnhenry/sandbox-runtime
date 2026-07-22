export { containsGlobCharsWin, stripExtendedPathPrefix, } from './sandbox-utils.js';
import type { SandboxDependencyCheck } from './linux-sandbox-utils.js';
import type { SrtWinConfig } from './sandbox-config.js';
/**
 * Windows sandbox backend.
 *
 * Network isolation is enforced by `srt-win.exe` — a Rust helper that
 * provisions a dedicated `srt-sandbox` local user account, installs a
 * machine-wide WFP filter set keyed on that account's SID, and
 * provides an `exec` subcommand that spawns the target via a two-hop
 * launch (broker → `CreateProcessWithLogonW(runner)` → runner →
 * restricted-token child) under `srt-sandbox`. The sandboxed child
 * reaches the host only via the JS mux proxy, which the caller
 * passes in via `--env`.
 *
 * The separate-user account structurally closes the surrogate-spawn
 * class (schtasks, `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, BITS,
 * RunAs="Interactive User" COM): the child's token carries a
 * different user SID, so it cannot reach real-user processes, tasks
 * register under `srt-sandbox`, and the user-SID WFP filter fences
 * `srt-sandbox` egress regardless of how the child was spawned.
 *
 * This module is a thin wrapper around the `srt-win` CLI; all status
 * comes from live enumeration. There is no marker file.
 *
 * Filesystem rules (`denyRead`/`denyWrite`/`allowRead`/`allowWrite`)
 * are enforced via additive explicit ACEs for `<sb-SID>` — see
 * {@link grantWindowsAcl} / {@link stampWindowsAcl}.
 */
export declare const DEFAULT_WINDOWS_PROXY_PORT_RANGE: readonly [number, number];
/**
 * `cannot-read` is the graceful-degrade state when BFE enumeration
 * is access-denied (it is admin-gated). The non-elevated readiness
 * check is {@link verifyWindowsWfpEgress}, not this enum.
 */
export type WindowsWfpStatus = 'absent' | 'installed' | 'cannot-read';
export interface WindowsWfpStatusResult {
    state: WindowsWfpStatus;
    /** Live filter count from BFE enum; `0` on `cannot-read`. */
    filters: number;
    /** `[low, high]` for the loopback PERMIT, when known. */
    portRange?: [number, number];
    /** Sandbox-user SID read from the first user-keyed filter tag. */
    userSid?: string;
    /**
     * Populated only on `cannot-read` (BFE enumeration is admin-gated;
     * a non-elevated caller can't read it). The non-elevated readiness
     * check is {@link verifyWindowsWfpEgress}, not this enum.
     */
    hint?: string;
}
/**
 * Result of `srt-win wfp verify` on success (exit 0, `blocked`) —
 * see {@link verifyWindowsWfpEgress}. Any other outcome throws, so
 * the tri-state is unobservable on the return path.
 */
export interface WindowsWfpVerifyResult {
    target: string;
    /** Runner's stderr (carries the `BLOCKED (…)` diagnostic line). */
    stderr: string;
}
/**
 * State of the `srt-sandbox` local account that `srt-win install`
 * provisions. The sandboxed child runs **as** this account.
 */
export interface WindowsSandboxUserStatus {
    /** The `srt-sandbox` local account exists. */
    provisioned: boolean;
    /** `S-1-5-21-…` of `srt-sandbox`, when provisioned. */
    sid?: string;
    /** The `sandbox-runtime-users` local group exists. */
    groupExists: boolean;
    /** `S-1-5-21-…` of `sandbox-runtime-users`, when it exists. */
    groupSid?: string;
    inBuiltinUsers: boolean;
    inSandboxGroup: boolean;
    hiddenFromLogon: boolean;
    /**
     * The credential row is present in `state.db` and readable by
     * THIS process. False when not yet written, or when called from
     * inside the sandbox (the state-DB directory carries an explicit
     * DENY for `sandbox-runtime-users` — machine-scope DPAPI alone
     * is not a confidentiality boundary).
     */
    credPresent: boolean;
    /** Setup marker schema version, when the marker row exists. */
    markerVersion?: number;
    /**
     * The calling (real) user's SID — the broker's identity, surfaced
     * for diagnostics. The DENY-ACE trustee is `srt-sandbox`'s SID
     * ({@link sid}), not this. Always present.
     */
    realUserSid: string;
    /**
     * SHA-1 thumbprint of the install-time CA, when one was
     * installed via `srt-win user trust-ca`. Uppercase hex.
     */
    caCertThumb?: string;
    /** PEM-encoded install-time CA certificate, when present. */
    caCertPem?: string;
}
/**
 * Inner shell to run `command` under, inside the sandbox: the
 * executable to spawn and the flag argv placed between it and the
 * user's command string. `exe` MUST originate from trusted host
 * configuration (user settings / install detection), NEVER from
 * workspace or repository content — the inner shell runs INSIDE the
 * sandbox so an unexpected path is not a sandbox-escape vector, but
 * it would still be an arbitrary-exec footgun if sourced from
 * untrusted input.
 *
 * Construct via {@link parseWindowsBinShell} — it is the SOLE
 * normalizer and the only place validation lives.
 */
export type WindowsBinShell = {
    /** Shell executable to spawn (absolute path when caller-supplied). */
    exe: string;
    /** Argv placed between `exe` and the user's command string. */
    args: readonly string[];
};
/**
 * Sole normalizer from the cross-platform `binShell?: string |
 * WindowsBinShell` surface ({@link SandboxManager.wrapWithSandboxArgv})
 * to a spawnable `{exe, args}` pair. All validation lives here —
 * {@link wrapCommandWithSandboxWindows} consumes the result verbatim.
 *
 * String form: bare token (`'cmd'|'pwsh'|'powershell'`) resolves to
 * the default install; absolute path to `bash.exe`/`sh.exe`/
 * `pwsh.exe`/`powershell.exe`/`cmd.exe` keeps the caller's path with
 * the matching flag shape. Object form: `exe` must be absolute; `args`
 * pass through unchanged. Throws on anything else — no silent
 * fallback to cmd.exe.
 *
 * Uses `path.win32` explicitly so the function (and its unit test)
 * is platform-independent.
 */
export declare function parseWindowsBinShell(raw?: string | WindowsBinShell): WindowsBinShell;
export interface WindowsSandboxParams {
    command: string;
    /**
     * JS HTTP proxy port — fed to `generateProxyEnvVars` for the env
     * overlay. With the in-process proxy this is the mux front-end
     * port (same as `socksProxyPort`).
     */
    httpProxyPort?: number;
    /**
     * JS SOCKS proxy port — fed to `generateProxyEnvVars` for the env
     * overlay. With the in-process proxy this is the mux front-end
     * port (same as `httpProxyPort`).
     */
    socksProxyPort?: number;
    /** Per-session proxy auth token; embedded in proxy env URLs. */
    proxyAuthToken?: string;
    /**
     * `mode: 'mask'` credential env vars — sentinel values the
     * sandboxed child should see in place of the real credentials.
     * Threaded through the `--env` overlay so the runner forwards
     * them into the child's fresh profile env (the broker's own
     * environment never reaches the child, so an `env -u`-style
     * scrub is structurally moot — there is no `unsetEnvVars`).
     * Applied BEFORE the proxy assignments so the sandbox's own
     * proxy plumbing survives even if a caller masks one of those
     * names — same precedence as macOS/Linux.
     */
    setEnvVars?: Readonly<Record<string, string>>;
    /**
     * Per-exec read-deny paths, applied via an additive
     * `(D;OICI;FA;;;<sb-SID>)` ACE under the `srt-win exec`
     * process's own PID and released after the child exits. Same
     * disk-first chokepoint as the session-level
     * {@link stampWindowsAcl}; same fail-closed semantics (exec
     * fails if any path cannot be stamped).
     *
     * Normalized concrete paths — globs expanded by the caller via
     * {@link expandWindowsFsPaths}, the same as session-level.
     * `srt-win exec`'s `canonicalize_ace_targets` hard-fails on a
     * glob (it never expands), so a `*`/`?` reaching this field is
     * a caller bug.
     */
    denyRead?: readonly string[];
    /** Per-exec write-deny paths — see {@link denyRead}. */
    denyWrite?: readonly string[];
    /**
     * Working directory the child starts in. Fed to
     * {@link buildGitConfigEnv} as a `safe.directory` entry so git
     * inside the sandbox accepts the real-user-owned working tree.
     * Default: `process.cwd()`.
     *
     * `srt-win exec` has no `--cwd` flag — the child's working
     * directory is whatever the caller passes as the spawn `{cwd:}`
     * option (broker `current_dir()` → runner `lpCurrentDirectory` →
     * child inherits). This field must match that spawn option so
     * `safe.directory` covers where git actually runs.
     */
    cwd?: string;
    /**
     * Session-level write-granted paths (the resolved
     * `filesystem.allowWrite` set). Each becomes a `safe.directory`
     * entry — see {@link buildGitConfigEnv}.
     */
    allowWrite?: readonly string[];
    /**
     * Path to the TLS-termination trust bundle (the MITM CA + system
     * roots) — fed to {@link generateProxyEnvVars} so the child's
     * `NODE_EXTRA_CA_CERTS` / `CURL_CA_BUNDLE` / `SSL_CERT_FILE` /
     * etc. point at it. Backslashes are normalised to forward slashes
     * before emission so the value survives msys2 env conversion AND
     * is accepted by native tools.
     *
     * The env-var layer covers OpenSSL-backed clients (msys2 curl,
     * openssl-backed git, node, python, cargo). Schannel/.NET clients
     * that read the Windows certificate store exclusively (System32
     * `curl.exe`, `Invoke-WebRequest`, Go-built tools) trust via the
     * separate `srt-win user trust-ca` / {@link windowsTrustCa}
     * install-time write into the sandbox user's `CurrentUser\Root`.
     *
     * The caller is responsible for the sandbox user having read
     * access to this path — `sandbox-manager.ts`'s `initialize()`
     * pushes it into the session's `acl grant` read-set alongside the
     * working-tree grants.
     */
    caCertPath?: string;
    /**
     * Suppress srt-win's informational stderr (progress lines,
     * per-exec-deny summary, seclogon-job note). Actual errors still
     * print. Default `true` — the host surfaces sandbox diagnostics
     * via its own debug log, not the child's stderr stream.
     */
    quiet?: boolean;
    /**
     * Resolved `srt-win` spawn descriptor — from
     * {@link resolveSrtWin}. Omit to resolve the packaged vendor
     * binary at call time.
     */
    srtWin?: SrtWinSpawn;
    /**
     * Inner shell. Defaults to `parseWindowsBinShell(undefined)`
     * (System32 cmd.exe). The child's post-`args` content is
     * **passthrough** — `&` chains, `"…"`/`'…'` quotes exactly as
     * written. The security boundary is at the OUTER spawn (this argv
     * is spawned with `shell:false`); the inner shell runs INSIDE the
     * sandbox so its metachars are the user's tool. Construct via
     * {@link parseWindowsBinShell}.
     */
    binShell?: WindowsBinShell;
}
/**
 * Locate the packaged `srt-win.exe`. Resolution order:
 *   1. `<root>/vendor/srt-win/{arch}/srt-win.exe` (prebuilt — published npm
 *      package, or after `npm run build:srt-win` locally).
 *   2. `<root>/vendor/srt-win-src/target/release/srt-win.exe` (local
 *      `cargo build --release` fallback for development).
 *
 * `<root>` is {@link repoRoot} — `__dirname/../..`, which resolves to the
 * repo root from `src/sandbox/` and `dist/sandbox/` alike, and to the
 * package root when installed under `node_modules`.
 *
 * Callers that ship their own binary (or a multicall binary that
 * routes on `argv[1] == `{@link SRT_WIN_DISPATCH_ARG1}) pass
 * `windows.srtWin` instead of relying on this lookup — see
 * {@link resolveSrtWin}.
 *
 * Resolution via the optional `@anthropic-ai/sandbox-runtime-win32-*`
 * platform packages is added separately.
 *
 * @throws if none exist.
 */
export declare function getSrtWinPath(): string;
/**
 * `argv[1]` sentinel a multicall embedder's dispatcher matches
 * against to route into `srt_win::run_from_args`. Mirrors the Rust
 * `srt_win::SRT_WIN_DISPATCH_ARG1`; the two MUST stay in sync.
 * `run_from_args` strips it before clap, so the standalone binary
 * accepts it harmlessly.
 */
export declare const SRT_WIN_DISPATCH_ARG1 = "--srt-win";
/**
 * Resolved `srt-win` spawn descriptor — the executable to load plus
 * the leading arguments that carry the dispatch sentinel. Threaded
 * to every spawn site so {@link resolveSrtWin} runs once (at
 * `initialize()`) instead of re-`stat`ing on every helper call.
 */
export type SrtWinSpawn = Readonly<{
    exe: string;
    prependArgs: readonly string[];
}>;
/**
 * Resolve the `srt-win` spawn target from config. When `cfg.path` is
 * set it is used verbatim (no fallback to the packaged binary — an
 * explicit override is a directive, not a hint) and
 * {@link SRT_WIN_DISPATCH_ARG1} is prepended so a multicall
 * dispatcher routes on `argv[1]`. When unset, falls back to
 * {@link getSrtWinPath} with no sentinel (the packaged binary
 * doesn't need it; `run_from_args` would strip it anyway).
 */
export declare function resolveSrtWin(cfg?: SrtWinConfig): SrtWinSpawn;
/**
 * Query the WFP filter set under the given sublayer via live BFE
 * enumeration. `installed` means at least one srt-win-tagged
 * `block-user` filter is present. Detection is **tag-based**
 * (providerData JSON); filters installed by other tooling without the
 * tag are not counted.
 *
 * BFE enumeration is admin-gated — a non-elevated caller gets
 * `state:"cannot-read"` with a `hint` (not an error). The
 * non-elevated readiness check is {@link verifyWindowsWfpEgress}.
 */
export declare function getWindowsWfpStatus(opts?: {
    sublayerGuid?: string;
    srtWin?: SrtWinSpawn;
}): WindowsWfpStatusResult;
/**
 * Behavioral proof that the WFP egress fence is active for the
 * sandbox user. Binds a local listener on an ephemeral loopback port
 * outside the WFP loopback-permit range, then spawns `srt-win
 * runner` as the sandbox user (via `CreateProcessWithLogonW`) to
 * attempt a direct TCP connect to it. The WFP block-user filter
 * fires at `ALE_AUTH_CONNECT` — before any packet leaves — so an
 * active fence yields WSAEACCES immediately and a missing fence lets
 * the connect through (the kernel completes the handshake against
 * the listening socket's backlog; no event-loop tick required, so
 * the synchronous `runSrtWin` is safe). Does not require elevation
 * and does not depend on any external host.
 *
 * `initialize()` calls this once per session, so a stale install
 * (sandbox user provisioned but filters since removed) fails closed
 * at session start instead of running every exec with full egress.
 *
 * @param opts.target overrides the probe target (skips the local
 *   listener bind).
 * @param opts.proxyPortRange the WFP loopback-permit range the
 *   listener must avoid. Default
 *   {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
 * @throws on any outcome other than `blocked` (exit 0).
 */
export declare function verifyWindowsWfpEgress(opts?: {
    target?: string;
    proxyPortRange?: readonly [number, number];
    srtWin?: SrtWinSpawn;
}): Promise<WindowsWfpVerifyResult>;
/**
 * Query the sandbox user account's provisioning state. Each field
 * is independently observed so a half-provisioned install (e.g.
 * user exists but credential file missing) is distinguishable.
 * Does not require elevation.
 */
export declare function getWindowsSandboxUserStatus(opts?: {
    srtWin?: SrtWinSpawn;
}): WindowsSandboxUserStatus;
/**
 * Read back the persistent MITM CA the sandbox was installed with
 * (via `srt-win user trust-ca` / {@link windowsTrustCa}).
 * Returns `null` when no CA was installed. The PEM is what `srt-win
 * user status` reconstructs from the DER stored in `state.db`.
 *
 * On Windows, `tlsTerminate` requires this CA to be present in the
 * sandbox user's `CurrentUser\Root` (schannel-level trust is an
 * install-time concern, not per-session); the host calls this from
 * `initialize()` to fail early with an actionable message when it
 * isn't.
 *
 * @param status pass an already-fetched
 *   {@link getWindowsSandboxUserStatus} result to avoid a second
 *   `srt-win user status` spawn.
 */
export declare function getWindowsSandboxCaCert(status?: WindowsSandboxUserStatus, opts?: {
    srtWin?: SrtWinSpawn;
}): {
    pem: string;
    thumb: string;
} | null;
/**
 * Install (or replace) the MITM CA in the **sandbox user's**
 * `CurrentUser\Root` and record it in `state.db` (so
 * {@link getWindowsSandboxCaCert} surfaces its thumbprint + PEM).
 * Thin wrapper around `srt-win user trust-ca <path>`. Does NOT
 * require elevation. Persistent until {@link uninstallWindowsSandbox}
 * deletes the sandbox user's profile.
 *
 * The CA has a separate lifecycle from {@link installWindowsSandbox}
 * — install provisions the account/filters and never touches the CA;
 * call this AFTER install when `tlsTerminate` will be used.
 *
 * @throws when the sandbox user is not provisioned, the file is not a
 *   parseable X.509 certificate, or the registry write into the
 *   sandbox user's hive fails.
 */
export declare function windowsTrustCa(caCertPath: string, opts?: {
    srtWin?: SrtWinSpawn;
}): void;
export interface WindowsInstallOptions {
    /** WFP sublayer GUID. Omit for srt-win's compile-time default. */
    sublayerGuid?: string;
    /**
     * Loopback PERMIT port range. Must match what
     * `SandboxRuntimeConfig.windows.proxyPortRange` will be set to.
     * Default {@link DEFAULT_WINDOWS_PROXY_PORT_RANGE}.
     */
    proxyPortRange?: readonly [number, number];
    /**
     * Name for the sandbox user account (created if absent, adopted
     * if it already exists as a local user). Default `srt-sandbox`.
     */
    sandboxUser?: string;
    /**
     * Replace an existing install whose configuration differs
     * (different port range or sandbox-user name under the same
     * sublayer). Without this, install refuses with "already
     * installed with different config" rather than silently
     * overwriting.
     */
    force?: boolean;
    /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
    srtWin?: SrtWinSpawn;
}
export interface WindowsInstallResult {
    /** Post-install WFP state. */
    wfp: WindowsWfpStatusResult;
    /** Post-install sandbox-user state. */
    user: WindowsSandboxUserStatus;
    /**
     * `true` if the user dismissed the UAC prompt. Not an error —
     * the install simply didn't happen. Re-run when the user is
     * ready to grant elevation.
     */
    cancelled?: true;
}
/**
 * One-shot install: provisions the `srt-sandbox` user account and
 * installs the user-SID-keyed WFP filter set — all in a single
 * self-elevating process (one UAC prompt). Idempotent; re-running
 * rotates the sandbox user's password.
 *
 * Network for the calling user is **not disrupted**: the filters key
 * on the `srt-sandbox` user's SID, so the broker, services, and
 * every other principal fall through to default-permit. No logout
 * is required.
 *
 * Returns the post-call WFP + sandbox-user state. If the user
 * cancels the UAC prompt this returns `{cancelled: true, …}` rather
 * than throwing — cancellation is a user choice, not an error.
 *
 * @throws on user/WFP creation failure, or if filters already exist
 *   under `sublayerGuid` with a different port range and `force` is
 *   not set.
 */
export declare function installWindowsSandbox(opts?: WindowsInstallOptions): WindowsInstallResult;
/**
 * Remove the WFP filter set under `sublayerGuid` and the
 * `srt-sandbox` account, its credential file, and the setup marker
 * (one UAC prompt). Idempotent.
 *
 * @returns `{cancelled: true}` if the user dismissed UAC.
 */
export declare function uninstallWindowsSandbox(opts?: {
    sublayerGuid?: string;
    keepUser?: boolean;
    srtWin?: SrtWinSpawn;
}): {
    cancelled?: true;
};
/**
 * Resolve any Windows filesystem-config path list — `allowRead`/
 * `allowWrite` grants and `denyRead`/`denyWrite` stamps — to
 * concrete existing paths via the single platform-aware
 * {@link normalizePathForSandbox} chokepoint (Linux/macOS parity:
 * point-in-time expansion at session initialize, not per-exec).
 * Glob patterns are expanded; non-glob paths are normalized and
 * returned 1:1. Missing paths are dropped (statSync probe).
 * Directory targets are accepted — the additive sandbox-user ACE
 * carries `(OI)(CI)` so it covers the subtree.
 */
export declare function expandWindowsFsPaths(patterns: readonly string[]): string[];
export interface WindowsAclStampOptions {
    /** Paths the sandboxed child must not read. */
    denyRead: readonly string[];
    /** Paths the sandboxed child must not write (read stays allowed). */
    denyWrite: readonly string[];
    /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
    sandboxUserSid: string;
    /** Long-lived host PID the holds are tied to. Default: this process. */
    holderPid?: number;
    /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
    srtWin?: SrtWinSpawn;
}
/**
 * Apply the file-deny ACE set for one host session: an additive
 * `(D;OICI;mask;;;<sb-SID>)` on the target plus a
 * `(D;OICI;FILE_DELETE_CHILD;;;<sb-SID>)` on the parent — no
 * PROTECTED rewrite, no SD snapshot. Idempotent and refcounted via
 * srt-win's `working_aces` table.
 *
 * Inputs are passed verbatim to `srt-win` (which canonicalizes and
 * rejects globs). Callers that accept globs should pre-expand via
 * {@link expandWindowsFsPaths}.
 *
 * @throws on exit ≠ 0 — including exit 2 (one or more inputs
 *   skipped). srt-win stamps the resolvable inputs before exiting
 *   2, so on throw the caller should call {@link restoreWindowsAcl}
 *   to release whatever WAS stamped.
 */
export declare function stampWindowsAcl(opts: WindowsAclStampOptions): void;
/**
 * Per-path outcome from `srt-win acl restore --json` /
 * `revoke --json`. The status set is intentionally loose: the
 * pre-/post- same-user-removal `srt-win` builds emit different
 * vocabularies for `restore` (`restored`/`leftChanged`/… vs
 * `revoked`/`stillHeld`/…). Callers (`reset()`) only log these,
 * so the union is whatever the binary on PATH says.
 */
export interface WindowsAclAceOutcome {
    path: string;
    status: string;
}
/**
 * Release this holder's deny ACEs and remove the sandbox-user ACE
 * on any path whose refcount falls to zero. Best-effort (does not
 * throw on per-path anomalies); returns per-path outcomes for the
 * caller to surface. Returns `undefined` only when `srt-win`
 * itself failed (no JSON to parse).
 */
export declare function restoreWindowsAcl(opts: {
    sandboxUserSid: string;
    holderPid?: number;
    srtWin?: SrtWinSpawn;
}): WindowsAclAceOutcome[] | undefined;
export interface WindowsAclGrantOptions {
    /** Paths to grant `MODIFY_NO_FDC` on (the working tree, `allowWrite`). */
    write: readonly string[];
    /** Paths to grant `FILE_GENERIC_READ|EXECUTE` on (`allowRead`). */
    read: readonly string[];
    /** SID of the dedicated sandbox user — {@link WindowsSandboxUserStatus.sid}. */
    sandboxUserSid: string;
    /** Long-lived host PID the holds are tied to. Default: this process. */
    holderPid?: number;
    /** Resolved `srt-win` spawn descriptor — from {@link resolveSrtWin}. */
    srtWin?: SrtWinSpawn;
}
/**
 * Apply per-session additive `(OI)(CI)` ALLOW ACEs for the sandbox
 * user on each path. The sandbox user has no inherent rights on
 * real-user-owned files; this is what makes the working tree (and
 * explicit `allowRead`/`allowWrite` paths) reachable from the
 * child. Idempotent and refcounted via srt-win's `working_aces`
 * table.
 *
 * @throws on exit ≠ 0. On throw the caller should call
 *   {@link revokeWindowsAcl} to release whatever WAS granted.
 */
export declare function grantWindowsAcl(opts: WindowsAclGrantOptions): void;
/**
 * Release this holder's grants and remove the sandbox-user ACE on
 * any path whose refcount falls to zero. Best-effort (does not
 * throw); logs anomalies.
 */
export declare function revokeWindowsAcl(opts: {
    sandboxUserSid: string;
    holderPid?: number;
    srtWin?: SrtWinSpawn;
}): WindowsAclAceOutcome[] | undefined;
/**
 * Build the `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_<n>` /
 * `GIT_CONFIG_VALUE_<n>` env-var set for the sandboxed child.
 *
 * Emits:
 *   - `safe.directory=<dir>` for each entry in `safeDirs` (or one
 *     `safe.directory=*` when the list is long) — the working tree
 *     is owned by the real user, so git running as `srt-sandbox`
 *     refuses with "detected dubious ownership" without it.
 *   - `http.schannelUseSSLCAInfo=true` and
 *     `http.schannelCheckRevoke=false` when `schannelCa` — makes
 *     git's default (schannel) backend honor `GIT_SSL_CAINFO`
 *     without `-c http.sslBackend=openssl`. Revocation is disabled
 *     because CryptoAPI CRL/OCSP fetches ignore proxy env and would
 *     be WFP-fenced.
 *
 * Composes with an existing `GIT_CONFIG_COUNT` in `baseEnv` by
 * continuing its numbering; the returned `GIT_CONFIG_COUNT` is the
 * new total. Under the two-hop launch the broker's own environment
 * never reaches the child, so `baseEnv` is the caller-supplied
 * overlay ({@link WindowsSandboxParams.setEnvVars}), not
 * `process.env`.
 *
 * Paths are emitted with forward slashes so the value survives
 * msys2's env conversion untouched and native git accepts it.
 */
export declare function buildGitConfigEnv(opts: {
    safeDirs: readonly string[];
    schannelCa: boolean;
    baseEnv?: Readonly<Record<string, string | undefined>>;
}): Record<string, string>;
/**
 * Build the spawn descriptor for running `command` inside the Windows
 * sandbox: an `argv` array plus the `env` to spawn it with.
 *
 * Caller MUST spawn the result with `{shell: false}` — that is the
 * security boundary that keeps untrusted bytes off the host's shell
 * (the inner `cmd.exe /c` runs INSIDE the sandbox; see
 * `vendor/srt-win-src/src/launch.rs` `build_cmdline` for the passthrough
 * rationale) — AND with the returned `env`.
 *
 * Proxy configuration is single-sourced by {@link generateProxyEnvVars}
 * (the same canonical builder used on macOS/Linux). `srt-win exec`
 * takes no `--http-proxy` / `--socks-proxy` flags and synthesizes no
 * proxy env. The two-hop runner starts with the SANDBOX user's
 * profile env (`USERPROFILE`/`TEMP` isolated) and overlays exactly
 * what we pass as `--env` — built here from the broker's `PATH` plus
 * the generated proxy set.
 */
export declare function wrapCommandWithSandboxWindows(p: WindowsSandboxParams): {
    argv: string[];
    env: NodeJS.ProcessEnv;
};
/**
 * Install instructions, surfaced verbatim in error messages.
 */
export declare function windowsInstallInstructions(sublayerGuid: string | undefined): string;
/**
 * Check the Windows backend is ready to sandbox. Errors block
 * `initialize()`; warnings are informational.
 */
export declare function checkWindowsDependencies(opts?: {
    sublayerGuid?: string;
    srtWin?: SrtWinSpawn;
}): SandboxDependencyCheck;
//# sourceMappingURL=windows-sandbox-utils.d.ts.map