import type { FsReadRestrictionConfig, FsWriteRestrictionConfig } from './sandbox-schemas.js';
import type { IgnoreViolationsConfig } from './sandbox-config.js';
export interface MacOSSandboxParams {
    command: string;
    needsNetworkRestriction: boolean;
    httpProxyPort?: number;
    socksProxyPort?: number;
    /** Per-session proxy auth token; embedded in proxy env URLs. */
    proxyAuthToken?: string;
    /** Path to the TLS-termination CA cert; injected as trust env vars. */
    caCertPath?: string;
    allowUnixSockets?: string[];
    allowAllUnixSockets?: boolean;
    allowLocalBinding?: boolean;
    allowMachLookup?: string[];
    readConfig: FsReadRestrictionConfig | undefined;
    writeConfig: FsWriteRestrictionConfig | undefined;
    /** Environment variable names to unset for the sandboxed child (env -u) */
    unsetEnvVars?: string[];
    /** Environment variables to set for the sandboxed child (env NAME=VALUE) */
    setEnvVars?: Record<string, string>;
    /**
     * Whole-file credential masks. SBPL cannot redirect reads, so on macOS
     * these degrade to read-deny on realPath until the DYLD interposer
     * lands. fakePath is unused here.
     */
    maskedFileBinds?: Array<{
        realPath: string;
        fakePath: string;
    }>;
    ignoreViolations?: IgnoreViolationsConfig | undefined;
    allowPty?: boolean;
    allowGitConfig?: boolean;
    enableWeakerNetworkIsolation?: boolean;
    allowAppleEvents?: boolean;
    binShell?: string;
}
/**
 * Get mandatory deny patterns as glob patterns (no filesystem scanning).
 * macOS sandbox profile supports regex/glob matching directly via globToRegex().
 */
export declare function macGetMandatoryDenyPatterns(allowGitConfig?: boolean): string[];
export interface SandboxViolationEvent {
    line: string;
    command?: string;
    encodedCommand?: string;
    timestamp: Date;
}
export type SandboxViolationCallback = (violation: SandboxViolationEvent) => void;
/**
 * Wrap command with macOS sandbox
 */
export declare function wrapCommandWithSandboxMacOS(params: MacOSSandboxParams): string;
/**
 * Start monitoring macOS system logs for sandbox violations
 * Look for sandbox-related kernel deny events ending in {logTag}
 */
export declare function startMacOSSandboxLogMonitor(callback: SandboxViolationCallback, ignoreViolations?: IgnoreViolationsConfig): () => void;
//# sourceMappingURL=macos-sandbox-utils.d.ts.map