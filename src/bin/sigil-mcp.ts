#!/usr/bin/env node
import { mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../audit/index.js';
import { HandleTable } from '../daemon/handles.js';
import { runMcpStdio } from '../mcp/server.js';

/**
 * sigil-mcp: single-process MCP server for sigil. Spawned by Claude Code per
 * session via the .claude/settings.json mcpServers entry.
 *
 * Lifecycle:
 *   - On startup: ensures ~/.sigil/{,keys/} exist (0o700), opens the audit
 *     log, constructs an EMPTY HandleTable. Keys are loaded later when the
 *     user runs `sigil unlock` (issue #23, phase B — adds a control socket
 *     this process opens, that the CLI connects to with the passphrase).
 *   - During the session: runs the MCP wire loop on stdio, dispatching tool
 *     calls in-process. Sign methods return DAEMON_LOCKED until the
 *     HandleTable is populated.
 *   - On stdin close (Claude exited): zeroizes the HandleTable, closes the
 *     audit writer, exits.
 */

const sigilHome = process.env['SIGIL_HOME'] ?? join(homedir(), '.sigil');
const keysDir = join(sigilHome, 'keys');
const auditPath = join(sigilHome, 'audit.log');

async function main(): Promise<void> {
  mkdirSync(sigilHome, { recursive: true, mode: 0o700 });
  mkdirSync(keysDir, { recursive: true, mode: 0o700 });

  // Start with an empty HandleTable. Unlock (phase B) will populate it.
  const handles = new HandleTable();
  const audit = new AuditWriter(auditPath);

  process.stderr.write(
    `sigil-mcp: ready (locked; run "sigil unlock" to load keys from ${keysDir})\n`,
  );

  const onShutdown = (): void => {
    handles.dispose();
    audit.close();
  };
  process.on('exit', onShutdown);
  process.on('SIGINT', () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));

  await runMcpStdio({
    context: { handles, audit },
    stdin: process.stdin,
    stdout: process.stdout,
    onLog: (e) => process.stderr.write(JSON.stringify(e) + '\n'),
  });

  // stdin closed (Claude exited)
  process.exit(0);
}

main().catch((err: Error) => {
  process.stderr.write(`sigil-mcp: ${err.message}\n`);
  process.exit(1);
});
