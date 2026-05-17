import { createConnection } from 'node:net';
import type { ControlRequest, ControlResponse } from './protocol.js';

const DEFAULT_TIMEOUT_MS = 5_000;

export interface ControlRequestOpts {
  /** Path of the control socket (defaults provided by callers). */
  socketPath: string;
  /** The request to send. */
  request: ControlRequest;
  /** Connect + I/O timeout (ms). Defaults to 5s. */
  timeoutMs?: number;
}

/**
 * Sends a single request to the running sigil-mcp control socket and returns
 * the parsed response. Throws ControlClientError if:
 *   - the socket file is missing or refused (server not running)
 *   - the connection times out
 *   - the response is not valid JSON
 *
 * Note: a server-side denial (wrong passphrase, etc.) is NOT thrown — it
 * comes back as a ControlResponse with `ok: false`. Callers branch on that.
 */
export async function controlRequest(opts: ControlRequestOpts): Promise<ControlResponse> {
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const sock = createConnection(opts.socketPath);
  sock.setEncoding('utf8');

  let timer: NodeJS.Timeout | null = null;
  const cleanupTimer = (): void => { if (timer) clearTimeout(timer); timer = null; };

  return new Promise<ControlResponse>((resolve, reject) => {
    timer = setTimeout(() => {
      sock.destroy();
      reject(new ControlClientError(`control socket timeout after ${timeoutMs}ms`, 'TIMEOUT'));
    }, timeoutMs);

    let buf = '';
    let resolved = false;
    const finish = (fn: () => void): void => {
      if (resolved) return;
      resolved = true;
      cleanupTimer();
      fn();
    };

    sock.on('connect', () => {
      sock.write(JSON.stringify(opts.request) + '\n');
    });
    sock.on('data', (chunk: string) => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl === -1) return;
      const line = buf.slice(0, nl);
      sock.end();
      try {
        const parsed = JSON.parse(line) as ControlResponse;
        finish(() => resolve(parsed));
      } catch {
        finish(() => reject(new ControlClientError(
          'control socket returned non-JSON response',
          'BAD_RESPONSE',
        )));
      }
    });
    sock.on('end', () => {
      if (!resolved) {
        if (buf.length === 0) {
          finish(() => reject(new ControlClientError(
            'control socket closed without sending a response',
            'NO_RESPONSE',
          )));
        }
      }
    });
    sock.on('error', (err: NodeJS.ErrnoException) => {
      const code = err.code;
      let mapped: ControlClientErrorCode = 'CONNECT_FAILED';
      if (code === 'ENOENT' || code === 'ECONNREFUSED') mapped = 'SERVER_DOWN';
      finish(() => reject(new ControlClientError(
        `control socket: ${err.message}`,
        mapped,
      )));
    });
  });
}

export type ControlClientErrorCode =
  | 'SERVER_DOWN'
  | 'CONNECT_FAILED'
  | 'TIMEOUT'
  | 'BAD_RESPONSE'
  | 'NO_RESPONSE';

export class ControlClientError extends Error {
  readonly code: ControlClientErrorCode;
  constructor(message: string, code: ControlClientErrorCode) {
    super(message);
    this.name = 'ControlClientError';
    this.code = code;
  }
}
