import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import { resolvePaths } from '../../src/cli/paths.js';
import { portalAdd } from '../../src/cli/portal.js';
import { status } from '../../src/cli/status.js';
import { startControlServer } from '../../src/control/index.js';
import { HandleTable } from '../../src/daemon/handles.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmpHome(): string { return mkdtempSync(join(tmpdir(), 'sigil-cli-status-')); }
const TEST_KDF = { m: 256, t: 1, p: 1 };

test('status: empty home reports zero keyfiles, mcp not running', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const report = await status(paths);
    equal(report.keyfilesOnDisk, 0);
    equal(report.mcpRunning, false);
    equal(report.mcpPid, null);
    equal(report.unlocked, false);
    equal(report.portals.length, 0);
    equal(report.auditLog, paths.auditLog);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: counts keyfiles in the keys directory', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const src = join(home, 'src.key');
    writeFileSync(src, priv(1));
    portalAdd(paths, { handle: 'evm:bot', keyFile: src, passphrase: Buffer.from('p'), kdfParams: TEST_KDF });

    const report = await status(paths);
    equal(report.keyfilesOnDisk, 1);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: reports mcpRunning=true when control server is alive (locked)', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const handles = new HandleTable();
    const audit = new AuditWriter(paths.auditLog);
    const ctl = await startControlServer({
      socketPath: paths.controlSocket,
      keysDir: paths.keysDir,
      policyDir: paths.policyDir,
      handles,
      pid: 42,
    });
    try {
      const report = await status(paths);
      equal(report.mcpRunning, true);
      equal(report.mcpPid, 42);
      equal(report.unlocked, false);
      equal(report.portals.length, 0);
    } finally {
      await ctl.close();
      handles.dispose();
      audit.close();
    }
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: reports unlocked + portals when control server is unlocked', async () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const handles = new HandleTable();
    handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
    handles.markUnlocked();
    const audit = new AuditWriter(paths.auditLog);
    const ctl = await startControlServer({
      socketPath: paths.controlSocket,
      keysDir: paths.keysDir,
      policyDir: paths.policyDir,
      handles,
      pid: 100,
    });
    try {
      const report = await status(paths);
      equal(report.mcpRunning, true);
      equal(report.unlocked, true);
      equal(report.portals.length, 1);
      equal(report.portals[0]!.handle, 'evm:bot');
      ok(report.portals[0]!.address.startsWith('0x'));
    } finally {
      await ctl.close();
      handles.dispose();
      audit.close();
    }
  } finally {
    rmSync(home, { recursive: true });
  }
});
