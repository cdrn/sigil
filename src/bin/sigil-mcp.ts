#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { AuditWriter } from '../audit/index.js';
import { resolvePaths } from '../cli/paths.js';
import { startControlServer } from '../control/index.js';
import { HandleTable } from '../daemon/handles.js';
import { runMcpStdio } from '../mcp/server.js';

/**
 * sigil-mcp: single-process MCP server for sigil. Spawned by Claude Code per
 * session via the .claude/settings.json mcpServers entry.
 *
 * Lifecycle:
 *   - On startup: ensures ~/.sigil/{,keys/} exist (0o700), opens the audit
 *     log, constructs an EMPTY (locked) HandleTable, binds the control
 *     socket at ~/.sigil/control.sock (0o600).
 *   - During the session: runs the MCP wire loop on stdio. Sign methods
 *     return DAEMON_LOCKED until the user runs `sigil unlock`, which pushes
 *     the passphrase over the control socket; the HandleTable loads the
 *     encrypted keyfiles from disk and the session is unlocked.
 *   - On stdin close (Claude exited): closes the control socket, locks +
 *     disposes the HandleTable, closes the audit writer, exits.
 *
 * The control socket is unref'd so it doesn't keep the loop alive on its own;
 * stdin alone gates process lifetime.
 */
async function main(): Promise<void> {
  const paths = resolvePaths(process.env);
  mkdirSync(paths.home, { recursive: true, mode: 0o700 });
  mkdirSync(paths.keysDir, { recursive: true, mode: 0o700 });

  const handles = new HandleTable();
  const audit = new AuditWriter(paths.auditLog);

  let controlClosed = false;
  let control;
  try {
    control = await startControlServer({
      socketPath: paths.controlSocket,
      keysDir: paths.keysDir,
      handles,
      onLog: (e) => process.stderr.write(`control: ${JSON.stringify(e)}\n`),
    });
  } catch (err) {
    process.stderr.write(`sigil-mcp: failed to bind control socket: ${(err as Error).message}\n`);
    handles.dispose();
    audit.close();
    process.exit(1);
  }

  process.stderr.write(
    `sigil-mcp: ready (locked; run "sigil unlock" to load keys from ${paths.keysDir})\n`,
  );

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
    context: { handles, audit },
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
