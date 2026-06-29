import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Resolves the locations sigil cares about, honouring SIGIL_HOME env override.
 * One source of truth used by the CLI, daemon entrypoint, and tests.
 *
 * The control directory holds one `<pid>.sock` per running sigil-mcp. Each
 * Claude Code session spawns its own sigil-mcp, which binds a socket named for
 * its PID; the `sigil` CLI fans `unlock`/`lock`/`status` out across every
 * socket in the directory (reaping any that are stale). The directory lives
 * inside ~/.sigil so it inherits the 0o700 permission; each socket file is
 * also chmod'd to 0o600 by the server on bind.
 */
export interface SigilPaths {
  readonly home: string;
  readonly keysDir: string;
  readonly policyDir: string;
  readonly controlDir: string;
  readonly auditLog: string;
  readonly configFile: string;
}

export function resolvePaths(env: NodeJS.ProcessEnv = process.env): SigilPaths {
  const home = env['SIGIL_HOME'] ?? join(homedir(), '.sigil');
  return {
    home,
    keysDir: join(home, 'keys'),
    policyDir: join(home, 'policy'),
    controlDir: env['SIGIL_CONTROL_DIR'] ?? join(home, 'control'),
    auditLog: join(home, 'audit.log'),
    configFile: join(home, 'config.toml'),
  };
}

/**
 * The control socket path for a single sigil-mcp instance, named for its PID.
 * Unique per live process, so two sessions never contend for the same path
 * (a same-PID collision only happens after PID reuse, which the server's
 * stale-socket recovery handles on bind).
 */
export function sessionSocketPath(controlDir: string, pid: number): string {
  return join(controlDir, `${pid}.sock`);
}
