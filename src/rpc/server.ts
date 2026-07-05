import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dispatch, RpcMethodError, type MethodContext } from '../daemon/index.js';
import { fillTransaction, FillParamsError } from './fill.js';
import {
  HttpUpstream,
  UpstreamRpcError,
  UpstreamTransportError,
  type JsonRpcUpstream,
} from './upstream.js';

/**
 * Local JSON-RPC signing proxy — the endpoint `forge script --unlocked`,
 * hardhat, cast, or any web3 tool points at. Serves three account methods
 * with the portal key and transparently proxies everything else to the
 * configured upstream node:
 *
 *   eth_accounts / eth_requestAccounts → [portal address]
 *   eth_signTransaction → fill nonce/gas/fees, sign, return raw tx hex
 *   eth_sendTransaction → same, then broadcast via upstream
 *                         eth_sendRawTransaction, return the tx hash
 *   everything else      → proxied verbatim to the upstream
 *
 * Security model — this is a NEW way to reach the portal key, so:
 *
 *   - Signing goes through the daemon's `dispatch()` — the byte-identical
 *     path the MCP tools use. Policy evaluation, the out-of-band confirm
 *     gate, and the hash-chained audit log apply to every request from this
 *     surface; there is no proxy-only signing branch that could drift.
 *   - The listener binds 127.0.0.1 only, and every request must carry the
 *     shared token from config (`Authorization: Bearer <token>`, or the
 *     password half of HTTP Basic — i.e. an rpc URL of the form
 *     http://sigil:<token>@127.0.0.1:8547 works out of the box with forge).
 *     Tokens are compared in constant time. Without the token, any local
 *     process could ask a permissive-mode portal to sign a drain.
 *   - The Host header must be a loopback name. A DNS-rebinding page makes
 *     the victim browser send its own hostname there; rejecting non-loopback
 *     Hosts kills that class even if the token somehow leaked into a URL.
 *   - Message-signing methods (eth_sign, personal_sign, eth_signTypedData*)
 *     are rejected, not proxied — they'd silently fail upstream, and sigil's
 *     MCP tools already cover them with their own policy toggles.
 *   - Fail-closed inheritance: locked table, policy deny, confirm deny or
 *     timeout, missing confirm transport — every one surfaces as a JSON-RPC
 *     error to the client and never yields a signature.
 *
 * No TLS: loopback-only, same rationale as the ack server.
 */

export interface RpcServerConfig {
  portal: string;
  upstream: string;
  token: string;
  port?: number;
}

export interface StartRpcServerOpts {
  config: RpcServerConfig;
  /** The SAME MethodContext the MCP loop uses — shared handles/audit/policy/confirm. */
  ctx: MethodContext;
  /** Injectable upstream for tests. Default: HttpUpstream(config.upstream). */
  upstream?: JsonRpcUpstream;
  /** Port override for tests (0 = kernel-assigned). Default: config.port ?? 8547. */
  port?: number;
  onLog?: (event: Record<string, unknown>) => void;
}

export interface RpcProxyServer {
  /** e.g. "http://127.0.0.1:8547" — no credentials embedded. */
  readonly url: string;
  readonly port: number;
  close(): Promise<void>;
}

export const DEFAULT_RPC_PORT = 8547;

/** Cap request bodies at 8 MiB — far above any deploy tx, far below a DoS. */
const MAX_BODY_BYTES = 8 * 1024 * 1024;

const SIGNING_METHODS_NOT_SUPPORTED = new Set([
  'eth_sign',
  'personal_sign',
  'eth_signTypedData',
  'eth_signTypedData_v3',
  'eth_signTypedData_v4',
]);

export function startRpcServer(opts: StartRpcServerOpts): Promise<RpcProxyServer> {
  const { config, ctx } = opts;
  const upstream = opts.upstream ?? new HttpUpstream(config.upstream);
  const log = opts.onLog ?? (() => {});
  const tokenDigest = sha256(config.token);
  // Upstream chain id, fetched once on first use. A node doesn't change
  // chains mid-life; if yours does, restart sigil-mcp.
  let chainIdPromise: Promise<bigint> | undefined;
  const getChainId = (): Promise<bigint> => {
    chainIdPromise ??= (async () => {
      const raw = await upstream.call('eth_chainId', []);
      if (typeof raw !== 'string' || !/^0x[0-9a-fA-F]+$/.test(raw)) {
        chainIdPromise = undefined; // retry on next request
        throw new UpstreamTransportError('upstream eth_chainId returned a malformed quantity');
      }
      return BigInt(raw);
    })();
    chainIdPromise.catch(() => { chainIdPromise = undefined; });
    return chainIdPromise;
  };

  const handleOne = async (req: unknown): Promise<Record<string, unknown> | null> => {
    if (typeof req !== 'object' || req === null || Array.isArray(req)) {
      return errorResponse(null, -32600, 'invalid request: not an object');
    }
    const r = req as Record<string, unknown>;
    const id = idOf(r);
    const method = r['method'];
    if (typeof method !== 'string') {
      return errorResponse(id, -32600, 'invalid request: method must be a string');
    }
    const params = r['params'] === undefined ? [] : r['params'];
    if (!Array.isArray(params)) {
      return errorResponse(id, -32602, `${method}: params must be an array`);
    }
    try {
      const result = await route(method, params);
      return { jsonrpc: '2.0', id, result };
    } catch (err) {
      return errorResponse(id, ...asJsonRpcError(err));
    }
  };

  const route = async (method: string, params: readonly unknown[]): Promise<unknown> => {
    switch (method) {
      case 'eth_accounts':
      case 'eth_requestAccounts': {
        // Locked table or missing portal → empty list, not an error: tools
        // poll this to display state, and an empty list is the truthful
        // answer to "which accounts can you sign for right now?".
        const portal = ctx.handles.isUnlocked()
          ? ctx.handles.list().find((p) => p.handle === config.portal)
          : undefined;
        return portal ? [portal.address] : [];
      }
      case 'eth_signTransaction':
      case 'eth_sendTransaction': {
        const raw = params[0];
        if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
          throw new FillParamsError(`${method}: params[0] must be a transaction object`);
        }
        const signed = await fillAndSign(raw as Record<string, unknown>);
        if (method === 'eth_signTransaction') return signed;
        return await upstream.call('eth_sendRawTransaction', [signed]);
      }
      default: {
        if (SIGNING_METHODS_NOT_SUPPORTED.has(method)) {
          throw new RpcMethodError(
            -32601,
            `${method} is not served by the sigil rpc proxy — message/typed-data ` +
            `signing is available through sigil's MCP tools with their own policy toggles`,
          );
        }
        // Transparent pass-through. Re-issued as a fresh request built from
        // {method, params} only — nothing else from the client survives.
        return await upstream.call(method, params);
      }
    }
  };

  const fillAndSign = async (raw: Record<string, unknown>): Promise<string> => {
    // Surface locked/missing-portal before any upstream round-trips.
    if (!ctx.handles.isUnlocked()) {
      throw new RpcMethodError(
        -32003,
        'sigil is locked — run "sigil unlock" in a terminal to load keys',
      );
    }
    const portal = ctx.handles.list().find((p) => p.handle === config.portal);
    if (!portal) {
      throw new RpcMethodError(-32000, `portal "${config.portal}" not found`);
    }
    const chainId = await getChainId();
    const tx = await fillTransaction(raw, {
      portalAddress: portal.address.toLowerCase(),
      chainId,
      upstream,
    });
    // The whole point: same dispatch as the MCP tools → same policy checks,
    // same confirm gate, same audit entries. This surface adds no privilege.
    const result = await dispatch(
      'sigil_eth_sign_transaction',
      { portal: config.portal, tx },
      ctx,
    ) as { signed: string };
    return result.signed;
  };

  const handler = (req: IncomingMessage, res: ServerResponse): void => {
    void handleHttp(req, res).catch((err: Error) => {
      log({ event: 'rpc_internal_error', message: err.message });
      if (!res.headersSent) {
        replyJson(res, 500, errorResponse(null, -32603, 'internal error'));
      } else {
        res.end();
      }
    });
  };

  const handleHttp = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    if (req.method !== 'POST') {
      replyText(res, 405, 'method not allowed — POST JSON-RPC 2.0 only\n');
      return;
    }
    if (!isLoopbackHost(req.headers.host)) {
      log({ event: 'rpc_rejected', reason: 'non-loopback host header' });
      replyText(res, 403, 'forbidden\n');
      return;
    }
    if (!isAuthorized(req.headers.authorization, tokenDigest)) {
      log({ event: 'rpc_rejected', reason: 'missing or invalid token' });
      replyText(res, 401, 'unauthorized — supply the [rpc] token via Bearer or Basic auth\n');
      return;
    }
    let body: Buffer;
    try {
      body = await readBody(req, MAX_BODY_BYTES);
    } catch {
      replyText(res, 413, 'payload too large\n');
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(body.toString('utf8'));
    } catch {
      replyJson(res, 200, errorResponse(null, -32700, 'parse error: body is not valid JSON'));
      return;
    }
    if (Array.isArray(parsed)) {
      if (parsed.length === 0) {
        replyJson(res, 200, errorResponse(null, -32600, 'invalid request: empty batch'));
        return;
      }
      const responses = await Promise.all(parsed.map(handleOne));
      replyJson(res, 200, responses.filter((r) => r !== null));
      return;
    }
    const response = await handleOne(parsed);
    replyJson(res, 200, response);
  };

  const server: Server = createServer(handler);
  const port = opts.port ?? config.port ?? DEFAULT_RPC_PORT;

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.removeListener('error', reject);
      const addr = server.address() as AddressInfo;
      const url = `http://127.0.0.1:${addr.port}`;
      log({ event: 'rpc_listening', url, portal: config.portal });
      resolve({
        url,
        port: addr.port,
        close: () =>
          new Promise<void>((res2, rej2) => {
            server.close((err) => (err ? rej2(err) : res2()));
          }),
      });
    });
  });
}

// ---------------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------------

function sha256(s: string): Buffer {
  return createHash('sha256').update(s, 'utf8').digest();
}

/** Constant-time token check against the config token's digest. Hashing both
 *  sides makes timingSafeEqual applicable to attacker-chosen lengths. */
function tokenMatches(candidate: string, tokenDigest: Buffer): boolean {
  return timingSafeEqual(sha256(candidate), tokenDigest);
}

function isAuthorized(header: string | undefined, tokenDigest: Buffer): boolean {
  if (typeof header !== 'string') return false;
  const space = header.indexOf(' ');
  if (space < 0) return false;
  const scheme = header.slice(0, space).toLowerCase();
  const rest = header.slice(space + 1).trim();
  if (scheme === 'bearer') {
    return tokenMatches(rest, tokenDigest);
  }
  if (scheme === 'basic') {
    let decoded: string;
    try {
      decoded = Buffer.from(rest, 'base64').toString('utf8');
    } catch {
      return false;
    }
    // The password half carries the token; the username is ignored, so both
    // http://sigil:TOKEN@… and http://:TOKEN@… work.
    const colon = decoded.indexOf(':');
    if (colon < 0) return false;
    return tokenMatches(decoded.slice(colon + 1), tokenDigest);
  }
  return false;
}

// ---------------------------------------------------------------------------
// DNS-rebinding defence
// ---------------------------------------------------------------------------

function isLoopbackHost(host: string | undefined): boolean {
  if (typeof host !== 'string' || host.length === 0) return false;
  let hostname: string;
  try {
    hostname = new URL(`http://${host}`).hostname;
  } catch {
    return false;
  }
  // WHATWG URL keeps the brackets on IPv6 hostnames ("[::1]"); strip them
  // so the comparison sees the bare address.
  const h = hostname.replace(/^\[|\]$/g, '').toLowerCase();
  return h === '127.0.0.1' || h === 'localhost' || h === '::1';
}

// ---------------------------------------------------------------------------
// Plumbing
// ---------------------------------------------------------------------------

function readBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let total = 0;
    req.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.destroy();
        reject(new Error('body too large'));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function idOf(r: Record<string, unknown>): string | number | null {
  const id = r['id'];
  if (typeof id === 'string' || typeof id === 'number') return id;
  return null;
}

function errorResponse(
  id: string | number | null,
  code: number,
  message: string,
  data?: unknown,
): Record<string, unknown> {
  return {
    jsonrpc: '2.0',
    id,
    error: { code, message, ...(data !== undefined ? { data } : {}) },
  };
}

/** Map every failure class onto a JSON-RPC error tuple. */
function asJsonRpcError(err: unknown): [number, string, unknown?] {
  if (err instanceof RpcMethodError) {
    // Sigil's daemon codes are already JSON-RPC-shaped (-32xxx); policy
    // denials, locked-daemon, invalid params all pass through unchanged.
    return err.data !== undefined ? [err.code, err.message, err.data] : [err.code, err.message];
  }
  if (err instanceof FillParamsError) {
    return [-32602, err.message];
  }
  if (err instanceof UpstreamRpcError) {
    return err.data !== undefined ? [err.code, err.message, err.data] : [err.code, err.message];
  }
  if (err instanceof UpstreamTransportError) {
    return [-32603, err.message];
  }
  return [-32603, `internal error: ${(err as Error).message}`];
}

function replyText(res: ServerResponse, status: number, body: string): void {
  res.writeHead(status, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end(body);
}

function replyJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(body));
}
