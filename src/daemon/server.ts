import { createServer, type Server, type Socket } from 'node:net';
import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { dispatch, RpcMethodError, type MethodContext } from './methods.js';
import {
  encodeError,
  encodeResponse,
  parseRequest,
  RPC_INTERNAL_ERROR,
  RPC_INVALID_REQUEST,
  RPC_PARSE_ERROR,
  type RpcId,
} from './rpc.js';

export interface DaemonServerOpts {
  socketPath: string;
  context: MethodContext;
  /**
   * Called for every connection that opens, with the peer socket. Useful for
   * tests; in production we don't need it.
   */
  onConnection?: (socket: Socket) => void;
  /**
   * Called when the server logs an event. Receives a structured payload.
   * Keep this lightweight; production wiring will swap in something real.
   */
  onLog?: (event: LogEvent) => void;
}

export type LogEvent =
  | { kind: 'listening'; path: string }
  | { kind: 'connection_open' }
  | { kind: 'connection_close' }
  | { kind: 'connection_error'; error: string }
  | { kind: 'request'; method: string; id: RpcId }
  | { kind: 'response'; id: RpcId; ok: boolean }
  | { kind: 'closed' };

export interface DaemonServerHandle {
  readonly server: Server;
  close: () => Promise<void>;
}

/**
 * Start a Unix-socket JSON-RPC server. The socket file is created at
 * `socketPath` with mode 0o600 (owner read/write only). If a stale socket
 * file exists at that path we remove it first.
 *
 * Each connection is line-delimited JSON: one request per line, one response
 * per line. Pipelining is supported (multiple requests per connection); they
 * are processed in order.
 */
export function startDaemonServer(opts: DaemonServerOpts): Promise<DaemonServerHandle> {
  const { socketPath, context } = opts;
  const log = (e: LogEvent) => opts.onLog?.(e);

  // If a stale file (e.g. from a crashed previous run) sits at the path,
  // remove it before binding. We don't check whether a process is actually
  // listening — that would need OS-specific calls. The 0o600 perms make it
  // impossible for another user to drop a file here.
  if (existsSync(socketPath)) {
    try { unlinkSync(socketPath); } catch { /* let listen() report the bind failure */ }
  }

  const server = createServer((socket) => {
    log({ kind: 'connection_open' });
    opts.onConnection?.(socket);

    let buf = '';

    socket.setEncoding('utf8');

    socket.on('data', (chunk) => {
      buf += chunk;
      let nl: number;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const line = buf.slice(0, nl);
        buf = buf.slice(nl + 1);
        if (line.length === 0) continue;
        const response = handleLine(line, context, log);
        socket.write(response + '\n');
      }
    });

    socket.on('error', (err) => {
      log({ kind: 'connection_error', error: err.message });
    });
    socket.on('close', () => {
      log({ kind: 'connection_close' });
    });
  });

  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(socketPath, () => {
      // Tighten perms — Node's default may be 0o755 depending on umask.
      try {
        chmodSync(socketPath, 0o600);
      } catch (err) {
        server.close();
        reject(err);
        return;
      }
      log({ kind: 'listening', path: socketPath });
      server.removeListener('error', reject);
      resolve({
        server,
        close: () =>
          new Promise<void>((res) => {
            server.close(() => {
              log({ kind: 'closed' });
              res();
            });
          }),
      });
    });
  });
}

function handleLine(
  line: string,
  context: MethodContext,
  log: (e: LogEvent) => void,
): string {
  const parsed = parseRequest(line);
  if (parsed.kind === 'parse_error') {
    log({ kind: 'response', id: null, ok: false });
    return encodeError(null, RPC_PARSE_ERROR, 'parse error');
  }
  if (parsed.kind === 'invalid') {
    log({ kind: 'response', id: parsed.id, ok: false });
    return encodeError(parsed.id, RPC_INVALID_REQUEST, parsed.reason);
  }
  const { request } = parsed;
  log({ kind: 'request', method: request.method, id: request.id });
  try {
    const result = dispatch(request.method, request.params, context);
    log({ kind: 'response', id: request.id, ok: true });
    return encodeResponse(request.id, result);
  } catch (err) {
    if (err instanceof RpcMethodError) {
      log({ kind: 'response', id: request.id, ok: false });
      return encodeError(request.id, err.code, err.message, err.data);
    }
    log({ kind: 'response', id: request.id, ok: false });
    return encodeError(
      request.id,
      RPC_INTERNAL_ERROR,
      `internal error: ${(err as Error).message}`,
    );
  }
}
