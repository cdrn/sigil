import { existsSync, readdirSync, statSync } from 'node:fs';
import { DaemonClient } from '../daemon/client.js';
import type { SigilPaths } from './paths.js';

export interface StatusReport {
  daemonRunning: boolean;
  socketPath: string;
  /** Present when the daemon responded to list_portals. */
  loadedPortals?: { handle: string; address: string }[];
  /** Set when we tried to talk to the daemon but it didn't respond. */
  daemonError?: string;
  /** Number of *.sigil files in the keys directory. */
  keyfilesOnDisk: number;
}

/**
 * Reports the current state: is sigild running, what portals does it have
 * loaded, how many keyfiles exist on disk. Does NOT require the passphrase
 * (so it's safe to run from a script).
 */
export async function status(paths: SigilPaths): Promise<StatusReport> {
  const report: StatusReport = {
    daemonRunning: false,
    socketPath: paths.socketPath,
    keyfilesOnDisk: countKeyfiles(paths.keysDir),
  };

  if (!existsSync(paths.socketPath)) return report;
  // Even if the socket file exists, the daemon may be dead. Try to connect.
  const client = new DaemonClient(paths.socketPath);
  try {
    await client.connect();
    const result = await client.call('sigil_list_portals', null) as {
      portals: { handle: string; address: string }[];
    };
    report.daemonRunning = true;
    report.loadedPortals = result.portals;
  } catch (err) {
    report.daemonError = (err as Error).message;
  } finally {
    client.close();
  }
  return report;
}

function countKeyfiles(dir: string): number {
  if (!existsSync(dir)) return 0;
  try {
    const stat = statSync(dir);
    if (!stat.isDirectory()) return 0;
  } catch {
    return 0;
  }
  return readdirSync(dir).filter((f) => f.endsWith('.sigil')).length;
}
