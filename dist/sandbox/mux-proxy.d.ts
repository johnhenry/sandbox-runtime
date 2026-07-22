import { type Server, type Socket } from 'node:net';
import type { Server as HttpServer } from 'node:http';
export interface MuxProxyOptions {
    /**
     * The HTTP CONNECT/absolute-URI proxy. Must NOT already be listening;
     * the mux owns its listen lifecycle (on a private unix socket on
     * macOS/Linux, or a localhost TCP port on Windows).
     */
    httpServer: HttpServer;
    /**
     * Per-connection SOCKS entry point. The mux calls this with a socket
     * whose peeked first byte has been `unshift()`ed back, so the handler
     * sees the full SOCKS greeting starting at byte 0.
     */
    handleSocksConnection: (socket: Socket) => void;
    /**
     * How long to wait for the client's first byte before destroying the
     * connection. Guards against connect-then-stall clients holding a slot.
     */
    firstByteTimeoutMs?: number;
    /**
     * Windows only: range the HTTP backend's TCP port must fall inside, so
     * the WFP loopback permit covers the mux→backend hop. Ignored on other
     * platforms (unix socket needs no port).
     */
    httpBackendPortRange?: readonly [number, number];
}
export interface MuxProxyServer {
    /** The front-end TCP listener. Call `.listen()` on this. */
    server: Server;
    /** Bound front-end port, once listening. */
    getPort(): number | undefined;
    /**
     * Start the HTTP backend listener (unix socket on macOS/Linux, localhost
     * TCP on Windows). Must be awaited before the front-end `.listen()`s so
     * an early HTTP connection never dispatches to an unbound backend.
     * Returns the backend's TCP port on Windows (so the caller can exclude
     * it when binding the front-end in the same range), or undefined on
     * unix-socket platforms.
     */
    listenHttpBackend(): Promise<number | undefined>;
    /** Tear down front-end, backend, and all open client sockets. */
    close(): Promise<void>;
    /** unref() both listeners so they don't keep the event loop alive. */
    unref(): void;
}
/**
 * Single-port proxy front-end that dispatches each connection to either the
 * SOCKS handler or the HTTP proxy based on the first byte the client sends.
 *
 * The HTTP leg cannot use `httpServer.emit('connection', socket)` because
 * Bun's `http.Server` does not implement that injection path (Node does).
 * Instead the HTTP backend listens on a private endpoint — a unix socket on
 * macOS/Linux, a localhost TCP port on Windows — and the mux pipes the
 * client socket to it. SOCKS connections are handed directly to the
 * library's per-connection entry, no extra hop.
 */
export declare function createMuxProxyServer(opts: MuxProxyOptions): MuxProxyServer;
//# sourceMappingURL=mux-proxy.d.ts.map