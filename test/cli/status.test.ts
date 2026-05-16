import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { HandleTable } from '../../src/daemon/handles.js';
import { startDaemonServer, type DaemonServerHandle } from '../../src/daemon/server.js';
import { resolvePaths } from '../../src/cli/paths.js';
import { portalAdd } from '../../src/cli/portal.js';
import { status } from '../../src/cli/status.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmpHome(): string { return mkdtempSync(join(tmpdir(), 'sigil-cli-status-')); }

test('status: daemon not running, no keys on disk', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const report = await status(paths);
    equal(report.daemonRunning, false);
    equal(report.keyfilesOnDisk, 0);
    equal(report.loadedPortals, undefined);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: counts keyfiles on disk even when daemon is down', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const src = join(home, 'src.key');
    writeFileSync(src, priv(1));
    portalAdd(paths, { handle: 'eth:bot', keyFile: src, passphrase: Buffer.from('p') });

    const report = await status(paths);
    equal(report.daemonRunning, false);
    equal(report.keyfilesOnDisk, 1);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: when daemon is up, returns loaded portals from the daemon', async () => {
  const home = mkTmpHome();
  let server: DaemonServerHandle | null = null;
  const handles = new HandleTable();
  const audit = new AuditWriter(join(home, 'audit.log'), { now: () => 1 });
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    handles.addEntry('eth:bot', new SecretBuffer(priv(1)));
    handles.addEntry('eth:executor', new SecretBuffer(priv(2)));
    server = await startDaemonServer({
      socketPath: paths.socketPath,
      context: { handles, audit },
    });

    const report = await status(paths);
    equal(report.daemonRunning, true);
    ok(report.loadedPortals);
    equal(report.loadedPortals!.length, 2);
  } finally {
    if (server) await server.close();
    audit.close();
    handles.dispose();
    rmSync(home, { recursive: true });
  }
});

test('status: stale socket file with no listener is reported as daemon down + error', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    // Create a fake file at the socket path so existsSync sees it,
    // but no listener is bound — connect should fail.
    writeFileSync(paths.socketPath, '');
    const report = await status(paths);
    equal(report.daemonRunning, false);
    ok(report.daemonError, 'expected an error message');
  } finally {
    rmSync(home, { recursive: true });
  }
});
