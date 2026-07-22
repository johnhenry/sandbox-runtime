// Library exports
export { SandboxManager } from './sandbox/sandbox-manager.js';
export { SandboxViolationStore } from './sandbox/sandbox-violation-store.js';
export { SandboxRuntimeConfigSchema, NetworkConfigSchema, FilesystemConfigSchema, CredentialsConfigSchema, IgnoreViolationsConfigSchema, RipgrepConfigSchema, } from './sandbox/sandbox-config.js';
// Windows install/status API
export { getSrtWinPath, resolveSrtWin, getWindowsWfpStatus, verifyWindowsWfpEgress, getWindowsSandboxUserStatus, getWindowsSandboxCaCert, windowsTrustCa, installWindowsSandbox, uninstallWindowsSandbox, windowsInstallInstructions, stampWindowsAcl, restoreWindowsAcl, grantWindowsAcl, revokeWindowsAcl, expandWindowsFsPaths, buildGitConfigEnv, parseWindowsBinShell, DEFAULT_WINDOWS_PROXY_PORT_RANGE, SRT_WIN_DISPATCH_ARG1, } from './sandbox/windows-sandbox-utils.js';
export { WindowsConfigSchema, SrtWinConfigSchema, } from './sandbox/sandbox-config.js';
// Utility functions
export { getDefaultWritePaths } from './sandbox/sandbox-utils.js';
// Platform utilities
export { getWslVersion } from './utils/platform.js';
//# sourceMappingURL=index.js.map