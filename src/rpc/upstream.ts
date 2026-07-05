/** Just enough of fetch for a JSON-RPC POST. Injectable for tests. */
export type RpcFetchLike = (
  url: string,
  init: {
    method: 'POST';
    headers: Record<string, string>;
    body: string;
    signal?: AbortSignal;
  },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/**
 * Minimal JSON-RPC 2.0 client for the upstream node the signing proxy
 * forwards to. Deliberately tiny: one method, no batching, no subscriptions —
 * the proxy re-issues each client request individually so nothing but a
 * `{method, params}` pair we constructed ourselves ever reaches the upstream
 * (no header or field smuggling from the proxy's clients).
 */
export interface JsonRpcUpstream {
  call(method: string, params: readonly unknown[]): Promise<unknown>;
}

/**
 * The upstream node answered with a JSON-RPC error object. Carries the
 * node's code/message/data so the proxy can hand them back to its own client
 * verbatim (forge's revert decoding depends on `data` surviving the trip).
 */
export class UpstreamRpcError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'UpstreamRpcError';
    this.code = code;
    this.data = data;
  }
}

/** Transport-level failure: unreachable, HTTP non-200, timeout, bad JSON. */
export class UpstreamTransportError extends Error {
  override readonly cause?: unknown;
  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'UpstreamTransportError';
    if (cause !== undefined) this.cause = cause;
  }
}

export interface HttpUpstreamOpts {
  /** Per-call timeout. Default 30s — covers slow public RPC endpoints. */
  timeoutMs?: number;
  /** Injectable for tests. Default: global fetch. */
  fetchImpl?: RpcFetchLike;
}

export class HttpUpstream implements JsonRpcUpstream {
  readonly #url: string;
  readonly #timeoutMs: number;
  readonly #fetch: RpcFetchLike;
  #nextId = 1;

  constructor(url: string, opts: HttpUpstreamOpts = {}) {
    this.#url = url;
    this.#timeoutMs = opts.timeoutMs ?? 30_000;
    this.#fetch = opts.fetchImpl ?? (globalThis.fetch as unknown as RpcFetchLike);
  }

  async call(method: string, params: readonly unknown[]): Promise<unknown> {
    let res: Awaited<ReturnType<RpcFetchLike>>;
    try {
      res = await this.#fetch(this.#url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: this.#nextId++, method, params }),
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch (err) {
      throw new UpstreamTransportError(
        `upstream RPC unreachable: ${(err as Error).message}`,
        err,
      );
    }
    if (!res.ok) {
      throw new UpstreamTransportError(`upstream RPC returned HTTP ${res.status}`);
    }
    let body: unknown;
    try {
      body = await res.json();
    } catch (err) {
      throw new UpstreamTransportError('upstream RPC returned invalid JSON', err);
    }
    if (typeof body !== 'object' || body === null || Array.isArray(body)) {
      throw new UpstreamTransportError('upstream RPC returned a non-object response');
    }
    const obj = body as Record<string, unknown>;
    const errObj = obj['error'];
    if (errObj !== undefined && errObj !== null) {
      if (typeof errObj === 'object' && !Array.isArray(errObj)) {
        const e = errObj as Record<string, unknown>;
        throw new UpstreamRpcError(
          typeof e['code'] === 'number' ? e['code'] : -32603,
          typeof e['message'] === 'string' ? e['message'] : 'upstream error',
          e['data'],
        );
      }
      throw new UpstreamTransportError('upstream RPC returned a malformed error object');
    }
    return obj['result'];
  }
}
