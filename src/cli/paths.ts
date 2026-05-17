import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Resolves the locations sigil cares about, honouring SIGIL_HOME env override.
 * One source of truth used by the CLI, daemon entrypoint, and tests.
 *
 * The control socket is where the running sigil-mcp listens for unlock/lock/
 * status commands from the `sigil` CLI. It lives inside ~/.sigil so it
 * inherits the 0o700 directory permission; the socket file itself is also
 * chmod'd to 0o600 by the server on bind.
 */
export interface SigilPaths {
  readonly home: string;
  readonly keysDir: string;
  readonly controlSocket: string;
  readonly auditLog: string;
}

export function resolvePaths(env: NodeJS.ProcessEnv = process.env): SigilPaths {
  const home = env['SIGIL_HOME'] ?? join(homedir(), '.sigil');
  return {
    home,
    keysDir: join(home, 'keys'),
    controlSocket: env['SIGIL_CONTROL_SOCK'] ?? join(home, 'control.sock'),
    auditLog: join(home, 'audit.log'),
  };
}
