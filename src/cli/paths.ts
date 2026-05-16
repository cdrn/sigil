import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Resolves the locations sigil cares about, honouring SIGIL_HOME env override.
 * One source of truth used by the CLI, daemon entrypoint, and tests.
 */
export interface SigilPaths {
  readonly home: string;
  readonly keysDir: string;
  readonly socketPath: string;
  readonly auditLog: string;
}

export function resolvePaths(env: NodeJS.ProcessEnv = process.env): SigilPaths {
  const home = env['SIGIL_HOME'] ?? join(homedir(), '.sigil');
  return {
    home,
    keysDir: join(home, 'keys'),
    socketPath: env['SIGIL_SOCK'] ?? join(home, 'sock'),
    auditLog: join(home, 'audit.log'),
  };
}
