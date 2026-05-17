import { chmodSync, existsSync, unlinkSync } from 'node:fs';
import { createConnection, createServer, type Server, type Socket } from 'node:net';
import { HandleLoadError, HandleTable } from '../daemon/handles.js';
import {
  CONTROL_SOCKET_VERSION,
  type ControlError,
  type ControlRequest,
  type ControlResponse,
  type ControlSuccess,
  parseControlRequest,
  type PortalSummary,
} from './protocol.js';

export interface ControlServerOpts {
  /** Path to bind the Unix socket. */
  socketPath: string;
  /** Directory of encrypted keyfiles to load on unlock. */
  keysDir: string;
  /** Live HandleTable shared with the MCP server. */
  handles: HandleTable;
  /** Optional log sink — defaults to no-op. */
  onLog?: (event: ControlLogEvent) => void;
  /** Optional process ID override (tests). */
  pid?: number;
}

export type ControlLogEvent =
  | { kind: 'listening'; path: string }
  | { kind: 'accepted' }
  | { kind: 'request'; method: string }
  | { kind: 'response'; ok: boolean; code?: string }
  | { kind: 'parse_error'; line: string }
  | { kind: 'stale_socket_cleared'; path: string }
  | { kind: 'bind_error'; error: string };

export interface ControlServerHandle {
  /** Returns when the server socket is closed (and the file unlinked). */
  close(): Promise<void>;
  /** The bound socket path (echoed back for convenience). */
  socketPath: string;
}

/**
 * Start a control listener bound to `socketPath`. Returns once the server is
 * listening. On EADDRINUSE, probes the existing socket: if it answers, throws
 * (a live sigil-mcp owns it); if it doesn't, unlinks the stale socket and
 * re-binds.
 *
 * The server is unref'd — it doesn't keep the event loop alive on its own,
 * so sigil-mcp can still exit when stdin closes.
 */
export async function startControlServer(opts: ControlServerOpts): Promise<ControlServerHandle> {
  const log = (e: ControlLogEvent): void => opts.onLog?.(e);
  const pid = opts.pid ?? process.pid;

  const server: Server = createServer((sock) => {
    handleConnection(sock, opts, pid, log).catch((err) => {
      log({ kind: 'bind_error', error: (err as Error).message });
      sock.destroy();
    });
  });
  server.unref();

  await bindWithStaleSocketRecovery(server, opts.socketPath, log);

  try {
    chmodSync(opts.socketPath, 0o600);
  } catch {
    // Best-effort; on some platforms this may not be needed.
  }
  log({ kind: 'listening', path: opts.socketPath });

  return {
    socketPath: opts.socketPath,
    close: () => new Promise<void>((resolve) => {
      server.close(() => {
        try { unlinkSync(opts.socketPath); } catch { /* may already be gone */ }
        resolve();
      });
    }),
  };
}

// ---------------------------------------------------------------------------
// Bind + stale-socket recovery
// ---------------------------------------------------------------------------

async function bindWithStaleSocketRecovery(
  server: Server,
  socketPath: string,
  log: (e: ControlLogEvent) => void,
): Promise<void> {
  try {
    await listen(server, socketPath);
    return;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== 'EADDRINUSE') throw err;
  }
  // Something is at the socket path. Probe it.
  const alive = await isSocketAlive(socketPath);
  if (alive) {
    throw new Error(
      `control socket ${socketPath} is already in use by another sigil-mcp process`,
    );
  }
  // Stale — unlink and retry.
  try { unlinkSync(socketPath); } catch { /* race: someone else cleaned it */ }
  log({ kind: 'stale_socket_cleared', path: socketPath });
  await listen(server, socketPath);
}

function listen(server: Server, socketPath: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error): void => {
      server.removeListener('listening', onListening);
      reject(err);
    };
    const onListening = (): void => {
      server.removeListener('error', onError);
      resolve();
    };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(socketPath);
  });
}

function isSocketAlive(socketPath: string): Promise<boolean> {
  if (!existsSync(socketPath)) return Promise.resolve(false);
  return new Promise((resolve) => {
    const sock = createConnection(socketPath);
    const cleanup = (alive: boolean): void => {
      sock.removeAllListeners();
      sock.destroy();
      resolve(alive);
    };
    sock.once('connect', () => cleanup(true));
    sock.once('error', () => cleanup(false));
  });
}

// ---------------------------------------------------------------------------
// Per-connection handler
// ---------------------------------------------------------------------------

async function handleConnection(
  sock: Socket,
  opts: ControlServerOpts,
  pid: number,
  log: (e: ControlLogEvent) => void,
): Promise<void> {
  log({ kind: 'accepted' });

  let buf = '';
  // Read until we have one line, then dispatch.
  const line = await new Promise<string | null>((resolve) => {
    sock.setEncoding('utf8');
    const onData = (chunk: string): void => {
      buf += chunk;
      const nl = buf.indexOf('\n');
      if (nl !== -1) {
        sock.off('data', onData);
        resolve(buf.slice(0, nl));
      }
    };
    sock.on('data', onData);
    sock.once('end', () => resolve(buf.length > 0 ? buf : null));
    sock.once('error', () => resolve(null));
  });

  if (line === null) {
    sock.end();
    return;
  }

  const parsed = parseControlRequest(line);
  if ('ok' in parsed && parsed.ok === false) {
    log({ kind: 'parse_error', line });
    write(sock, parsed);
    return;
  }
  const request = parsed as ControlRequest;
  log({ kind: 'request', method: request.method });

  const response = dispatch(request, opts, pid);
  log({ kind: 'response', ok: response.ok, ...(response.ok ? {} : { code: response.code }) });
  write(sock, response);
}

function write(sock: Socket, resp: ControlResponse): void {
  sock.end(JSON.stringify(resp) + '\n');
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

function dispatch(
  req: ControlRequest,
  opts: ControlServerOpts,
  pid: number,
): ControlResponse {
  switch (req.method) {
    case 'status':
      return statusResponse(opts.handles, pid);
    case 'lock':
      opts.handles.lock();
      return statusResponse(opts.handles, pid);
    case 'unlock':
      return doUnlock(req.passphraseB64, opts, pid);
  }
}

function doUnlock(passphraseB64: string, opts: ControlServerOpts, pid: number): ControlResponse {
  if (opts.handles.isUnlocked()) {
    return {
      ok: false,
      code: 'ALREADY_UNLOCKED',
      error: 'sigil is already unlocked; run "sigil lock" first to re-unlock',
    };
  }
  let passphrase: Buffer;
  try {
    passphrase = Buffer.from(passphraseB64, 'base64');
  } catch {
    return { ok: false, code: 'INVALID_REQUEST', error: 'passphraseB64 is not valid base64' };
  }
  try {
    opts.handles.loadFromDir(opts.keysDir, passphrase);
  } catch (err) {
    if (err instanceof HandleLoadError) {
      // Distinguish wrong-passphrase from other load failures so the CLI can
      // suggest re-running unlock specifically.
      if (/wrong passphrase|tampered/.test(err.message)) {
        return { ok: false, code: 'WRONG_PASSPHRASE', error: err.message };
      }
      return { ok: false, code: 'KEYS_LOAD_FAILED', error: err.message };
    }
    return { ok: false, code: 'INTERNAL', error: (err as Error).message };
  } finally {
    passphrase.fill(0);
  }
  return statusResponse(opts.handles, pid);
}

function statusResponse(handles: HandleTable, pid: number): ControlSuccess {
  const portals: PortalSummary[] = handles.isUnlocked()
    ? handles.list().map((p) => ({ handle: p.handle, kind: p.kind, address: p.address }))
    : [];
  return {
    ok: true,
    version: CONTROL_SOCKET_VERSION,
    pid,
    unlocked: handles.isUnlocked(),
    portals,
  };
}
