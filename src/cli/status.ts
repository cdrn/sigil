import { existsSync, readdirSync, statSync } from 'node:fs';
import { broadcast, isControlError, type PortalSummary } from '../control/index.js';
import type { SigilPaths } from './paths.js';

export interface SessionStatus {
  /** Process ID of the running sigil-mcp. */
  pid: number;
  /** Whether this session's HandleTable is unlocked. */
  unlocked: boolean;
  /** Portals loaded in this session (empty when locked). */
  portals: PortalSummary[];
}

export interface StatusReport {
  /** Number of *.sigil files in the keys directory. */
  keyfilesOnDisk: number;
  /** Path the audit log lives at. Useful for `tail`-ing during incidents. */
  auditLog: string;
  /** True if at least one sigil-mcp session answered the control socket. */
  mcpRunning: boolean;
  /** Per-session live state, one entry per reachable sigil-mcp. */
  sessions: SessionStatus[];
}

/**
 * Reports the on-disk + live state of sigil. Does NOT require the passphrase.
 *
 * Disk side: counts encrypted keyfiles.
 * Live side: fans a status probe out across every per-session control socket.
 * Each reachable sigil-mcp contributes a SessionStatus; stale sockets (from
 * hard-killed sessions) are reaped during the broadcast. When no Claude Code
 * session is open, `sessions` is empty and `mcpRunning` is false.
 */
export async function status(paths: SigilPaths): Promise<StatusReport> {
  const keyfilesOnDisk = countKeyfiles(paths.keysDir);
  const results = await broadcast(paths.controlDir, { method: 'status' }, 1_000);
  const sessions: SessionStatus[] = [];
  for (const r of results) {
    if (r.response && !isControlError(r.response)) {
      sessions.push({
        pid: r.response.pid,
        unlocked: r.response.unlocked,
        portals: r.response.portals,
      });
    }
  }
  sessions.sort((a, b) => a.pid - b.pid);
  return {
    keyfilesOnDisk,
    auditLog: paths.auditLog,
    mcpRunning: sessions.length > 0,
    sessions,
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
