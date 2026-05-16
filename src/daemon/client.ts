import { connect, type Socket } from 'node:net';
import type { RpcId, RpcResponse } from './rpc.js';

/**
 * Connects to a sigild Unix-socket and provides a typed `call` method that
 * round-trips JSON-RPC requests. Supports multiple concurrent in-flight
 * requests via id correlation.
 *
 * The client is single-connection; if the connection drops, every pending
 * call rejects and the client must be reconstructed.
 */
export class DaemonClient {
  readonly socketPath: string;
  #sock: Socket | null = null;
  #buf = '';
  #nextId = 1;
  #pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
  #closed = false;

  constructor(socketPath: string) {
    this.socketPath = socketPath;
  }

  connect(): Promise<void> {
    if (this.#sock) return Promise.resolve();
    return new Promise((resolve, reject) => {
      const sock = connect(this.socketPath);
      sock.setEncoding('utf8');
      const onConnectError = (err: Error): void => {
        sock.removeListener('connect', onConnect);
        reject(err);
      };
      const onConnect = (): void => {
        sock.removeListener('error', onConnectError);
        this.#sock = sock;
        sock.on('data', (chunk) => this.#onData(chunk as unknown as string));
        sock.on('error', (err) => this.#onError(err));
        sock.on('close', () => this.#onClose());
        resolve();
      };
      sock.once('error', onConnectError);
      sock.once('connect', onConnect);
    });
  }

  call(method: string, params: unknown): Promise<unknown> {
    if (this.#closed) return Promise.reject(new Error('DaemonClient is closed'));
    if (!this.#sock) return Promise.reject(new Error('DaemonClient is not connected'));
    const id = this.#nextId++;
    return new Promise((resolve, reject) => {
      this.#pending.set(id, { resolve, reject });
      this.#sock!.write(JSON.stringify({ jsonrpc: '2.0', id, method, params }) + '\n');
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    if (this.#sock) {
      this.#sock.end();
    }
    this.#failAllPending(new Error('client closed'));
  }

  #onData(chunk: string): void {
    this.#buf += chunk;
    let nl: number;
    while ((nl = this.#buf.indexOf('\n')) !== -1) {
      const line = this.#buf.slice(0, nl);
      this.#buf = this.#buf.slice(nl + 1);
      if (line.length === 0) continue;
      this.#handleLine(line);
    }
  }

  #handleLine(line: string): void {
    let resp: RpcResponse;
    try {
      resp = JSON.parse(line) as RpcResponse;
    } catch {
      // Daemon should never send malformed JSON; if it does, the connection
      // is corrupt — fail everything pending.
      this.#failAllPending(new Error(`daemon sent malformed JSON: ${line.slice(0, 80)}`));
      return;
    }
    const id = this.#extractId(resp.id);
    if (id === null) return; // unsolicited (no pending caller to resolve)
    const pending = this.#pending.get(id);
    if (!pending) return;
    this.#pending.delete(id);
    if ('error' in resp) {
      const e = resp.error;
      pending.reject(new DaemonRpcError(e.code, e.message, e.data));
    } else if ('result' in resp) {
      pending.resolve(resp.result);
    } else {
      pending.reject(new Error('daemon response had neither result nor error'));
    }
  }

  #extractId(raw: RpcId): number | null {
    return typeof raw === 'number' ? raw : null;
  }

  #onError(err: Error): void {
    this.#failAllPending(err);
  }

  #onClose(): void {
    this.#sock = null;
    this.#failAllPending(new Error('daemon socket closed'));
  }

  #failAllPending(err: Error): void {
    for (const p of this.#pending.values()) p.reject(err);
    this.#pending.clear();
  }
}

export class DaemonRpcError extends Error {
  readonly code: number;
  readonly data: unknown;
  constructor(code: number, message: string, data?: unknown) {
    super(message);
    this.name = 'DaemonRpcError';
    this.code = code;
    this.data = data;
  }
}
