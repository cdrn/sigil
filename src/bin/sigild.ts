#!/usr/bin/env node
import { homedir } from 'node:os';
import { join } from 'node:path';
import { readPassphrase } from '../daemon/passphrase.js';
import { runDaemon } from '../daemon/runtime.js';

const sigilHome = process.env['SIGIL_HOME'] ?? join(homedir(), '.sigil');

let shutting = false;

async function main(): Promise<void> {
  const handle = await runDaemon({
    sigilHome,
    passphrase: () => readPassphrase('sigil passphrase: '),
    onLog: (e) => process.stderr.write(JSON.stringify(e) + '\n'),
  });

  process.stderr.write(
    `sigild ready: ${handle.portals} portal(s) loaded, listening on ${handle.socketPath}\n`,
  );

  const shutdown = async (signal: string): Promise<void> => {
    if (shutting) return;
    shutting = true;
    process.stderr.write(`sigild: ${signal} received, shutting down\n`);
    await handle.shutdown();
    process.exit(0);
  };

  process.on('SIGINT', () => { void shutdown('SIGINT'); });
  process.on('SIGTERM', () => { void shutdown('SIGTERM'); });
}

main().catch((err: Error) => {
  process.stderr.write(`sigild: ${err.message}\n`);
  process.exit(1);
});
