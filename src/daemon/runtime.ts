import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { AuditWriter } from '../audit/index.js';
import { HandleTable } from './handles.js';
import { startDaemonServer, type DaemonServerHandle, type LogEvent } from './server.js';

export interface DaemonRuntimeOpts {
  /** Sigil home directory. Defaults to $SIGIL_HOME or ~/.sigil. */
  sigilHome: string;
  /** Returns the unlock passphrase. Called once at startup; the runtime zeroes it after use. */
  passphrase: () => Promise<Buffer> | Buffer;
  /** Optional log sink for daemon and server events. */
  onLog?: (event: LogEvent | RuntimeEvent) => void;
}

export type RuntimeEvent =
  | { kind: 'runtime_starting'; sigilHome: string }
  | { kind: 'runtime_ready'; portals: number; socketPath: string }
  | { kind: 'runtime_shutdown_begin' }
  | { kind: 'runtime_shutdown_complete' };

export interface DaemonRuntimeHandle {
  readonly socketPath: string;
  readonly auditPath: string;
  readonly portals: number;
  readonly server: DaemonServerHandle;
  shutdown: () => Promise<void>;
}

/**
 * Bring up the daemon: ensure directories exist, prompt for the passphrase,
 * load every keyfile from <sigilHome>/keys, open the audit log, and start
 * the Unix-socket server. The returned handle exposes a single `shutdown`
 * function that closes the server, closes the audit writer, and zeroes
 * every key in memory.
 *
 * The runtime is testable end-to-end by passing a `passphrase` callback that
 * returns a known buffer and pointing `sigilHome` at a tmpdir.
 */
export async function runDaemon(opts: DaemonRuntimeOpts): Promise<DaemonRuntimeHandle> {
  const log = (e: LogEvent | RuntimeEvent): void => opts.onLog?.(e);
  const sigilHome = opts.sigilHome;
  const keysDir = join(sigilHome, 'keys');
  const auditPath = join(sigilHome, 'audit.log');
  const socketPath = join(sigilHome, 'sock');

  log({ kind: 'runtime_starting', sigilHome });

  mkdirSync(sigilHome, { recursive: true, mode: 0o700 });
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });

  const passphrase = await opts.passphrase();
  const handles = new HandleTable();
  try {
    handles.loadFromDir(keysDir, passphrase);
  } finally {
    passphrase.fill(0);
  }

  const audit = new AuditWriter(auditPath);
  const server = await startDaemonServer({
    socketPath,
    context: { handles, audit },
    ...(opts.onLog ? { onLog: (e: LogEvent) => opts.onLog!(e) } : {}),
  });

  log({ kind: 'runtime_ready', portals: handles.list().length, socketPath });

  let shutdownPromise: Promise<void> | null = null;
  const shutdown = (): Promise<void> => {
    if (shutdownPromise) return shutdownPromise;
    log({ kind: 'runtime_shutdown_begin' });
    shutdownPromise = (async () => {
      await server.close();
      audit.close();
      handles.dispose();
      log({ kind: 'runtime_shutdown_complete' });
    })();
    return shutdownPromise;
  };

  return {
    socketPath,
    auditPath,
    portals: handles.list().length,
    server,
    shutdown,
  };
}
