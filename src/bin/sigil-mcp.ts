#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { AuditWriter } from '../audit/index.js';
import { resolvePaths, sessionSocketPath } from '../cli/paths.js';
import { startControlServer } from '../control/index.js';
import { HandleTable } from '../daemon/handles.js';
import { runMcpStdio } from '../mcp/server.js';
import { FileSystemPolicyResolver } from '../policy/index.js';

/**
 * sigil-mcp: single-process MCP server for sigil. Spawned by Claude Code per
 * session via the .claude/settings.json mcpServers entry.
 *
 * Lifecycle:
 *   - On startup: ensures ~/.sigil/{,keys/,control/} exist (0o700), opens the
 *     audit log, constructs an EMPTY (locked) HandleTable, binds a per-session
 *     control socket at ~/.sigil/control/<pid>.sock (0o600).
 *   - During the session: runs the MCP wire loop on stdio. Sign methods
 *     return DAEMON_LOCKED until the user runs `sigil unlock`, which pushes
 *     the passphrase over the control socket; the HandleTable loads the
 *     encrypted keyfiles from disk and the session is unlocked.
 *   - On stdin close (Claude exited): closes the control socket, locks +
 *     disposes the HandleTable, closes the audit writer, exits.
 *
 * Each session owns a distinct socket (named for its PID), so multiple Claude
 * windows no longer contend for a single control.sock — `sigil unlock` fans
 * out across every socket in the directory and unlocks them all at once.
 *
 * The control socket is unref'd so it doesn't keep the loop alive on its own;
 * stdin alone gates process lifetime.
 */
async function main(): Promise<void> {
  const paths = resolvePaths(process.env);
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.policyDir, { recursive: true, mode: 0o700 });
  mkdirSync(paths.controlDir, { recursive: true, mode: 0o700 });
  const socketPath = sessionSocketPath(paths.controlDir, process.pid);

  const handles = new HandleTable();
  const audit = new AuditWriter(paths.auditLog);
  const policy = new FileSystemPolicyResolver(paths.policyDir);

  let controlClosed = false;
  let control: Awaited<ReturnType<typeof startControlServer>> | null = null;
  try {
    control = await startControlServer({
      socketPath,
      keysDir: paths.keysDir,
      policyDir: paths.policyDir,
      handles,
      onLog: (e) => process.stderr.write(`control: ${JSON.stringify(e)}\n`),
    });
  } catch (err) {
    // The per-PID socket is ours alone, so this is genuinely exceptional
    // (e.g. controlDir not writable). Stay up so the MCP stdio still works,
    // but warn — without a control socket this session can't be unlocked and
    // sign calls will return DAEMON_LOCKED.
    process.stderr.write(
      `sigil-mcp: control socket unavailable at ${socketPath} (${(err as Error).message}). ` +
      `This session will stay locked; sign calls will return DAEMON_LOCKED.\n`,
    );
  }

  if (control) {
    process.stderr.write(
      `sigil-mcp: ready (locked; run "sigil unlock" to load keys from ${paths.keysDir})\n`,
    );
  } else {
    process.stderr.write(`sigil-mcp: ready (locked — no control socket; cannot be unlocked)\n`);
  }

  const shutdown = (): void => {
    handles.dispose();
    audit.close();
    if (!controlClosed && control) {
      controlClosed = true;
      control.close().catch(() => { /* best-effort */ });
    }
  };
  process.on('exit', shutdown);
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));

  await runMcpStdio({
    context: { handles, audit, policy },
    stdin: process.stdin,
    stdout: process.stdout,
    onLog: (e) => process.stderr.write(JSON.stringify(e) + '\n'),
  });

  // stdin closed (Claude exited) — close the control socket explicitly so
  // we don't leave a stale socket file behind.
  if (control && !controlClosed) {
    controlClosed = true;
    await control.close();
  }
  process.exit(0);
}

main().catch((err: Error) => {
  process.stderr.write(`sigil-mcp: ${err.message}\n`);
  process.exit(1);
});
