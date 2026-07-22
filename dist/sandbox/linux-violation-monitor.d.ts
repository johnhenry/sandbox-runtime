import type { SandboxViolationCallback } from './macos-sandbox-utils.js';
import type { IgnoreViolationsConfig } from './sandbox-config.js';
export interface LinuxViolationMonitorOptions {
    /**
     * Paths bwrap mounts read-write. apply-seccomp's USER_NOTIF observer
     * reports every write-intent syscall (allowed or not, since the BPF filter
     * cannot see the mount table); a path is treated as a violation only when
     * it is *not* under any of these prefixes, or when it falls under
     * {@link denyWritePaths}.
     */
    allowWritePaths: string[];
    /** Paths bwrap re-mounts read-only inside an allowWrite region. */
    denyWritePaths: string[];
    ignoreViolations?: IgnoreViolationsConfig;
}
export interface LinuxViolationMonitor {
    /** Filesystem unix-socket path the listener is bound to. Bind-mount this
     *  into each bwrap sandbox and pass it to apply-seccomp via
     *  SRT_OBSERVE_SOCK. `undefined` if listen() failed (the caller should
     *  proceed without observation). */
    observeSocketPath: string | undefined;
    /** Resolves once the listener is bound, or on listen failure. */
    ready: Promise<void>;
    stop: () => void;
}
/**
 * Linux equivalent of {@link startMacOSSandboxLogMonitor}. Creates a single
 * filesystem unix-socket listener; each `apply-seccomp` instance's outer stub
 * connects to it and writes one JSON line per observed write-intent syscall.
 * The supervise loop lives inside `apply-seccomp` itself (the parent that
 * already waitpid()s the workload), so there is no separate supervisor binary.
 *
 * Unlike Seatbelt's `log stream`, the kernel reports *attempts* here, not
 * denials, so this function intersects each path against the configured
 * allow/deny set before forwarding it as a violation.
 *
 * The reported path is read out of the (untrusted) sandboxed process's memory
 * with process_vm_readv and is therefore ATTACKER-CONTROLLED and racy. bwrap's
 * mount table is the only enforcement boundary; the violation events emitted
 * here are diagnostic hints and must never gate a policy decision.
 *
 * The transport is a *filesystem* unix socket because bwrap runs with
 * `--unshare-net` (abstract sockets are net-namespace-scoped) and bwrap closes
 * inherited fds. Filesystem sockets survive across net + user + mount
 * namespaces as long as the path is bind-mounted into the sandbox.
 */
export declare function startLinuxSandboxViolationMonitor(callback: SandboxViolationCallback, opts: LinuxViolationMonitorOptions): LinuxViolationMonitor;
//# sourceMappingURL=linux-violation-monitor.d.ts.map