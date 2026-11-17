import { HttpUpstream, type JsonRpcUpstream } from '../rpc/upstream.js';
import { DEFAULT_SIM_TIMEOUT_MS, withTimeout } from './simulate.js';

/**
 * Chain id → simulation node, built from config at sigil-mcp boot.
 *
 * Sources, in order:
 *   1. `[simulate.rpc]` — explicit per-chain URLs. One HttpUpstream per
 *      chain, created on first use and cached.
 *   2. The `[rpc]` proxy's upstream, for whichever chain it serves. Its
 *      chain is not known from config, so it is asked (eth_chainId) the
 *      first time a chain without an explicit entry needs a simulator. A
 *      failed lookup means "no simulator for this chain" and is retried
 *      after a cool-down, so a node that's down at boot doesn't disable
 *      simulation for the whole session — and one that stays down doesn't
 *      cost every sign a timeout.
 *
 * Nothing here ever throws to the caller: an unresolvable chain is simply
 * `undefined`, which the preview reports as "skipped" and the policy's
 * require_simulation turns into a deny.
 */
export interface SimulatorResolverOpts {
  rpcByChain: ReadonlyMap<bigint, string>;
  /** `[rpc].upstream`, when the signing proxy is configured. */
  proxyUpstream?: string;
  /** Per-call timeout for the nodes created here. */
  timeoutMs?: number;
  /** Injectable for tests. Default: HttpUpstream. */
  makeUpstream?: (url: string, timeoutMs: number) => JsonRpcUpstream;
  /** Clock for the failure cool-down. */
  now?: () => number;
}

/** How long a failed eth_chainId lookup on the proxy upstream is remembered. */
const PROXY_RETRY_MS = 60_000;

export class SimulatorResolver {
  readonly #urls: ReadonlyMap<bigint, string>;
  readonly #proxyUrl: string | undefined;
  readonly #timeoutMs: number;
  readonly #make: (url: string, timeoutMs: number) => JsonRpcUpstream;
  readonly #now: () => number;
  readonly #cache = new Map<bigint, JsonRpcUpstream>();
  #proxy: JsonRpcUpstream | undefined;
  #proxyChain: Promise<bigint | null> | undefined;
  #proxyFailedAt = -Infinity;

  constructor(opts: SimulatorResolverOpts) {
    this.#urls = opts.rpcByChain;
    this.#proxyUrl = opts.proxyUpstream;
    this.#timeoutMs = opts.timeoutMs ?? DEFAULT_SIM_TIMEOUT_MS;
    this.#make = opts.makeUpstream ?? ((url, timeoutMs) => new HttpUpstream(url, { timeoutMs }));
    this.#now = opts.now ?? (() => Date.now());
  }

  /** Chains with an explicit `[simulate.rpc]` entry, ascending. */
  get configuredChains(): bigint[] {
    return [...this.#urls.keys()].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  }

  get hasProxyFallback(): boolean {
    return this.#proxyUrl !== undefined;
  }

  simulatorFor(
    chainId: bigint,
  ): JsonRpcUpstream | undefined | Promise<JsonRpcUpstream | undefined> {
    const cached = this.#cache.get(chainId);
    if (cached) return cached;
    const url = this.#urls.get(chainId);
    if (url !== undefined) {
      const up = this.#make(url, this.#timeoutMs);
      this.#cache.set(chainId, up);
      return up;
    }
    if (this.#proxyUrl === undefined) return undefined;
    return this.#viaProxy(chainId);
  }

  async #viaProxy(chainId: bigint): Promise<JsonRpcUpstream | undefined> {
    if (this.#proxyChain === undefined) {
      if (this.#now() - this.#proxyFailedAt < PROXY_RETRY_MS) return undefined;
      this.#proxy ??= this.#make(this.#proxyUrl!, this.#timeoutMs);
      const proxy = this.#proxy;
      this.#proxyChain = withTimeout(
        proxy.call('eth_chainId', []),
        this.#timeoutMs,
        'eth_chainId timed out',
      )
        .then((v) => {
          if (typeof v === 'string' && /^0x[0-9a-fA-F]+$/.test(v)) return BigInt(v);
          throw new Error('malformed eth_chainId');
        })
        .catch(() => {
          // Forget the attempt so a later sign (after the cool-down) retries.
          this.#proxyChain = undefined;
          this.#proxyFailedAt = this.#now();
          return null;
        });
    }
    const served = await this.#proxyChain;
    if (served === null || served !== chainId) return undefined;
    this.#cache.set(chainId, this.#proxy!);
    return this.#proxy;
  }
}
