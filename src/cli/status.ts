import { existsSync, readdirSync, statSync } from 'node:fs';
import type { SigilPaths } from './paths.js';

export interface StatusReport {
  /** Number of *.sigil files in the keys directory. */
  keyfilesOnDisk: number;
  /** Path the audit log lives at. Useful for `tail`-ing during incidents. */
  auditLog: string;
  /**
   * Whether `sigil-mcp` appears to be running (control socket exists).
   * Always false in phase A; populated in phase B when the control socket lands.
   */
  mcpRunning: boolean;
}

/**
 * Reports the on-disk state of sigil. Does NOT require the passphrase.
 *
 * Phase A scope: just counts keyfiles. Phase B will add probing the control
 * socket to determine whether sigil-mcp is alive, and whether it's unlocked.
 */
export function status(paths: SigilPaths): StatusReport {
  return {
    keyfilesOnDisk: countKeyfiles(paths.keysDir),
    auditLog: paths.auditLog,
    mcpRunning: false,
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
