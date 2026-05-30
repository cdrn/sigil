import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { runCli } from '../../src/cli/main.js';

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }
function mkTmpHome(): string { return mkdtempSync(join(tmpdir(), 'sigil-cli-main-')); }

// Test-only fast KDF — see PortalAddOpts.kdfParams.
const TEST_KDF = { m: 256, t: 1, p: 1 };

function capture(): { stdout: Writable; stderr: Writable; out: () => string; err: () => string } {
  const outBuf: string[] = [];
  const errBuf: string[] = [];
  return {
    stdout: new Writable({ write(c, _e, cb) { outBuf.push(c.toString()); cb(); } }),
    stderr: new Writable({ write(c, _e, cb) { errBuf.push(c.toString()); cb(); } }),
    out: () => outBuf.join(''),
    err: () => errBuf.join(''),
  };
}

test('runCli: --help prints usage and exits 0', async () => {
  const cap = capture();
  const r = await runCli({ argv: ['--help'], stdout: cap.stdout, stderr: cap.stderr });
  equal(r.code, 0);
  ok(/Usage:/.test(cap.out()));
});

test('runCli: no args also prints usage', async () => {
  const cap = capture();
  const r = await runCli({ argv: [], stdout: cap.stdout, stderr: cap.stderr });
  equal(r.code, 0);
  ok(/Usage:/.test(cap.out()));
});

test('runCli: unknown subcommand exits 2 with usage', async () => {
  const cap = capture();
  const r = await runCli({ argv: ['mystery'], stdout: cap.stdout, stderr: cap.stderr });
  equal(r.code, 2);
  ok(/unknown subcommand/.test(cap.err()));
});

test('runCli: portal add — successful flow', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/added evm:bot/.test(cap.out()));
    // Source removed, encrypted keyfile present.
    equal(existsSync(srcKey), false);
    ok(existsSync(join(home, 'keys', 'evm:bot.sigil')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal add — missing --key-file exits 2', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'add', 'evm:bot'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 2);
    ok(/--key-file/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal list — empty', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'list'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/\(no portals\)/.test(cap.out()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal list — shows handles and addresses', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    // Add first.
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: new Writable({ write(_c, _e, cb) { cb(); } }),
      stderr: new Writable({ write(_c, _e, cb) { cb(); } }),
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    // Then list.
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'list'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/evm:bot\t0x/.test(cap.out()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal qr — prints address, a QR block, and the address again', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: new Writable({ write(_c, _e, cb) { cb(); } }),
      stderr: new Writable({ write(_c, _e, cb) { cb(); } }),
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'qr', 'evm:bot'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    const out = cap.out();
    // Address printed twice (above + below the QR), case-preserving.
    const addr = out.match(/0x[0-9a-fA-F]{40}/g);
    ok(addr !== null && addr.length >= 2, 'address printed at least twice');
    equal(addr![0], addr![1]);
    // QR block characters present.
    ok(out.includes('██'));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal qr — missing handle exits 2 with usage', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'qr'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 2);
    ok(/missing handle/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal qr — unknown handle exits 1 with helpful error', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'qr', 'evm:nope'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 1);
    ok(/not found/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal remove — success and not-found cases', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: new Writable({ write(_c, _e, cb) { cb(); } }),
      stderr: new Writable({ write(_c, _e, cb) { cb(); } }),
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });

    const cap1 = capture();
    const r1 = await runCli({
      argv: ['portal', 'remove', 'evm:bot'],
      stdout: cap1.stdout, stderr: cap1.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r1.code, 0);
    ok(/removed evm:bot/.test(cap1.out()));

    const cap2 = capture();
    const r2 = await runCli({
      argv: ['portal', 'remove', 'evm:bot'],
      stdout: cap2.stdout, stderr: cap2.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r2.code, 1);
    ok(/not found/.test(cap2.out()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: status — empty home reports zero keyfiles, mcp not running', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['status'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 0);
    const parsed = JSON.parse(cap.out()) as { mcpRunning: boolean; keyfilesOnDisk: number };
    equal(parsed.mcpRunning, false);
    equal(parsed.keyfilesOnDisk, 0);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: passphrase buffer is zeroed after portal add', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const pass = Buffer.from('hunter2');
    const passCopy = Array.from(pass);
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: new Writable({ write(_c, _e, cb) { cb(); } }),
      stderr: new Writable({ write(_c, _e, cb) { cb(); } }),
      env: { SIGIL_HOME: home },
      passphrase: () => pass,
      kdfParams: TEST_KDF,
    });
    // After the CLI returns, the original buffer should be zeroed.
    ok(passCopy.some((b) => b !== 0)); // sanity: was non-zero
    for (const b of pass) equal(b, 0);
  } finally {
    rmSync(home, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Policy CLI surface
// ---------------------------------------------------------------------------

test('runCli: portal add — writes permissive policy by default', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/policy: permissive/.test(cap.out()));
    ok(existsSync(join(home, 'policy', 'evm:bot.toml')));
    const pol = readFileSync(join(home, 'policy', 'evm:bot.toml'), 'utf8');
    ok(/mode = "permissive"/.test(pol));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal new generates a fresh key with permissive policy', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'new', 'evm:fresh'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/generated evm:fresh \(0x[0-9a-f]{40}\)/.test(cap.out()));
    ok(/policy: permissive/.test(cap.out()));
    ok(existsSync(join(home, 'keys', 'evm:fresh.sigil')));
    ok(existsSync(join(home, 'policy', 'evm:fresh.toml')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal new --strict writes the strict template', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'new', 'evm:cold', '--strict'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/policy: strict/.test(cap.out()));
    ok(/note: strict policy denies/.test(cap.out()));
    const pol = readFileSync(join(home, 'policy', 'evm:cold.toml'), 'utf8');
    ok(/mode = "strict"/.test(pol));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal new without handle errors with usage', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'new'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 2);
    ok(/missing handle/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: portal add --strict writes the strict template', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const cap = capture();
    const r = await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey, '--strict'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(r.code, 0);
    ok(/policy: strict/.test(cap.out()));
    ok(/note: strict policy denies/.test(cap.out()));
    const pol = readFileSync(join(home, 'policy', 'evm:bot.toml'), 'utf8');
    ok(/mode = "strict"/.test(pol));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: policy show — prints the file contents', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    // Provision first.
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey, '--strict'],
      stdout: new Writable({ write(_c, _e, cb) { cb(); } }),
      stderr: new Writable({ write(_c, _e, cb) { cb(); } }),
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    // Now show.
    const cap = capture();
    const r = await runCli({
      argv: ['policy', 'show', 'evm:bot'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 0);
    ok(/mode = "strict"/.test(cap.out()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: policy show — exits 1 if file missing', async () => {
  const home = mkTmpHome();
  try {
    const cap = capture();
    const r = await runCli({
      argv: ['policy', 'show', 'evm:nope'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 1);
    ok(/no file/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: policy init — provisions a policy file for an existing portal', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, Buffer.from('11'.repeat(32), 'hex'));
    // Add the portal (creates both keyfile and policy file).
    let cap = capture();
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: { m: 256, t: 1, p: 1 },
    });
    // Delete the policy file as if it never existed (older sigil version).
    rmSync(join(home, 'policy', 'evm:bot.toml'));

    cap = capture();
    const r = await runCli({
      argv: ['policy', 'init', 'evm:bot'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 0);
    ok(/wrote permissive policy/.test(cap.out()));
    ok(existsSync(join(home, 'policy', 'evm:bot.toml')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: policy init <handle> --strict — writes strict template', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, Buffer.from('22'.repeat(32), 'hex'));
    let cap = capture();
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: { m: 256, t: 1, p: 1 },
    });
    rmSync(join(home, 'policy', 'evm:bot.toml'));

    cap = capture();
    const r = await runCli({
      argv: ['policy', 'init', 'evm:bot', '--strict'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 0);
    ok(/wrote strict policy/.test(cap.out()));
    ok(/strict policy denies everything/.test(cap.out()));
    const pol = readFileSync(join(home, 'policy', 'evm:bot.toml'), 'utf8');
    ok(/mode = "strict"/.test(pol));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('runCli: policy init — refuses if policy already exists', async () => {
  const home = mkTmpHome();
  try {
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, Buffer.from('33'.repeat(32), 'hex'));
    let cap = capture();
    await runCli({
      argv: ['portal', 'add', 'evm:bot', '--key-file', srcKey],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
      passphrase: () => Buffer.from('p'),
      kdfParams: { m: 256, t: 1, p: 1 },
    });
    // policy file exists from portal add — init should refuse.
    cap = capture();
    const r = await runCli({
      argv: ['policy', 'init', 'evm:bot'],
      stdout: cap.stdout, stderr: cap.stderr,
      env: { SIGIL_HOME: home },
    });
    equal(r.code, 1);
    ok(/already exists/.test(cap.err()));
  } finally {
    rmSync(home, { recursive: true });
  }
});
