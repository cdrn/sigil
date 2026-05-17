import { existsSync, readdirSync, statSync } from 'node:fs';
import {
  ControlClientError,
  controlRequest,
  isControlError,
  type PortalSummary,
} from '../control/index.js';
import type { SigilPaths } from './paths.js';

export interface StatusReport {
  /** Number of *.sigil files in the keys directory. */
  keyfilesOnDisk: number;
  /** Path the audit log lives at. Useful for `tail`-ing during incidents. */
  auditLog: string;
  /** True if the control socket responded — i.e. sigil-mcp is alive. */
  mcpRunning: boolean;
  /** Process ID of the running sigil-mcp; null when not running. */
  mcpPid: number | null;
  /** True if the HandleTable has been unlocked. False when mcp is down or locked. */
  unlocked: boolean;
  /** Portals currently loaded in the running sigil-mcp. Empty when locked or down. */
  portals: PortalSummary[];
}

/**
 * Reports the on-disk + live state of sigil. Does NOT require the passphrase.
 *
 * Disk side: counts encrypted keyfiles.
 * Live side: probes the control socket. If the server is unreachable, marks
 * mcpRunning=false; this is the common case when no Claude Code session is
 * open. Any other client error is also treated as not-running — the user
 * can re-run "sigil unlock" or check the socket file directly for more
 * detailed diagnosis.
 */
export async function status(paths: SigilPaths): Promise<StatusReport> {
  const keyfilesOnDisk = countKeyfiles(paths.keysDir);
  let mcpRunning = false;
  let mcpPid: number | null = null;
  let unlocked = false;
  let portals: PortalSummary[] = [];
  try {
    const resp = await controlRequest({
      socketPath: paths.controlSocket,
      request: { method: 'status' },
      timeoutMs: 1_000,
    });
    if (!isControlError(resp)) {
      mcpRunning = true;
      mcpPid = resp.pid;
      unlocked = resp.unlocked;
      portals = resp.portals;
    }
  } catch (err) {
    if (!(err instanceof ControlClientError)) throw err;
    // SERVER_DOWN / CONNECT_FAILED / TIMEOUT all → mcpRunning=false.
  }
  return {
    keyfilesOnDisk,
    auditLog: paths.auditLog,
    mcpRunning,
    mcpPid,
    unlocked,
    portals,
  };
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
