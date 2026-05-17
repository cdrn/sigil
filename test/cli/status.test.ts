import { test } from 'node:test';
import { equal } from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolvePaths } from '../../src/cli/paths.js';
import { portalAdd } from '../../src/cli/portal.js';
import { status } from '../../src/cli/status.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmpHome(): string { return mkdtempSync(join(tmpdir(), 'sigil-cli-status-')); }
const TEST_KDF = { m: 256, t: 1, p: 1 };

test('status: empty home reports zero keyfiles, mcp not running', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const report = status(paths);
    equal(report.keyfilesOnDisk, 0);
    equal(report.mcpRunning, false);
    equal(report.auditLog, paths.auditLog);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('status: counts keyfiles in the keys directory', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const src = join(home, 'src.key');
    writeFileSync(src, priv(1));
    portalAdd(paths, { handle: 'eth:bot', keyFile: src, passphrase: Buffer.from('p'), kdfParams: TEST_KDF });

    const report = status(paths);
    equal(report.keyfilesOnDisk, 1);
  } finally {
    rmSync(home, { recursive: true });
  }
});
