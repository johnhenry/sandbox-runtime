import type { Socket } from 'net';
import type { ResolvedParentProxy } from './parent-proxy.js';
export interface SocksProxyServerOptions {
    filter(port: number, host: string): Promise<boolean> | boolean;
    /**
     * Optional upstream HTTP proxy. When present, SOCKS CONNECT requests are
     * tunnelled through the parent's HTTP CONNECT instead of dialing directly.
     * NO_PROXY-matched hosts still connect directly.
     */
    parentProxy?: ResolvedParentProxy;
    /**
     * Per-session token (same value as the HTTP proxy's). When set, the
     * server requires SOCKS5 username/password auth and only accepts
     * user "srt" with this token as the password.
     */
    proxyAuthToken?: string;
}
export interface SocksProxyWrapper {
    /**
     * Hand an already-accepted socket to the SOCKS state machine. Used by the
     * mux front-end after first-byte sniffing. The socket must carry the full
     * SOCKS greeting starting at byte 0 (i.e. any peeked bytes already
     * `unshift()`ed back). Replicates the library's own accept path
     * (`setNoDelay()` + `_handleConnection`) and tracks the socket so
     * `close()` can force-destroy it.
     */
    handleConnection(socket: Socket): void;
    /** Force-destroy all injected connections. */
    close(): Promise<void>;
}
export declare function createSocksProxyServer(options: SocksProxyServerOptions): SocksProxyWrapper;
//# sourceMappingURL=socks-proxy.d.ts.map