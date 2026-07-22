/**
 * Bind `server` to the first free port in `range`, retrying on EADDRINUSE.
 * With `range` undefined, binds to ephemeral port 0 once. The Windows WFP
 * loopback permit is installed by range, so proxy listeners on Windows must
 * land inside it; other platforms bake the actual ephemeral port into the
 * sandbox profile and pass `range = undefined`.
 */
export declare function listenInRange(server: {
    once(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown;
    removeListener(ev: 'error' | 'listening', cb: (e?: Error) => void): unknown;
}, doListen: (port: number) => void, range: readonly [number, number] | undefined, exclude: ReadonlySet<number>): Promise<void>;
//# sourceMappingURL=listen-in-range.d.ts.map