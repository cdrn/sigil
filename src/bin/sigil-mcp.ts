#!/usr/bin/env node
import { homedir } from 'node:os';
import { join } from 'node:path';
import { DaemonClient } from '../daemon/client.js';
import { runMcpStdio } from '../mcp/server.js';

const sigilHome = process.env['SIGIL_HOME'] ?? join(homedir(), '.sigil');
const socketPath = process.env['SIGIL_SOCK'] ?? join(sigilHome, 'sock');

async function main(): Promise<void> {
  const daemon = new DaemonClient(socketPath);
  try {
    await daemon.connect();
  } catch (err) {
    process.stderr.write(
      `sigil-mcp: failed to connect to sigild at ${socketPath}: ${(err as Error).message}\n` +
      `Is sigild running? Start it with "sigild" or "sigil up" (once the CLI lands).\n`,
    );
    process.exit(1);
  }

  process.stderr.write(`sigil-mcp: connected to sigild at ${socketPath}\n`);

  await runMcpStdio({
    daemon,
    stdin: process.stdin,
    stdout: process.stdout,
    onLog: (e) => process.stderr.write(JSON.stringify(e) + '\n'),
  });

  daemon.close();
}

main().catch((err: Error) => {
  process.stderr.write(`sigil-mcp: ${err.message}\n`);
  process.exit(1);
});
