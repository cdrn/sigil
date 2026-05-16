import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unsealKey } from '../../src/crypto/index.js';
import { addressFromPrivateKey } from '../../src/eth/index.js';
import { resolvePaths } from '../../src/cli/paths.js';
import { portalAdd, portalListFromDisk, portalRemove } from '../../src/cli/portal.js';

function mkTmpHome(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-cli-portal-'));
}

function priv(b: number): Buffer { const p = Buffer.alloc(32); p[31] = b; return p; }

// Test-only fast KDF params so a portal add is milliseconds, not seconds.
const TEST_KDF = { m: 256, t: 1, p: 1 };

test('portalAdd: writes encrypted keyfile and returns derived address', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const result = portalAdd(paths, {
      handle: 'eth:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    equal(result.address, addressFromPrivateKey(priv(1)));
    ok(existsSync(result.keyfilePath));
    // Source key was removed by default.
    equal(existsSync(srcKey), false);
    // Keyfile is 0o600.
    equal((statSync(result.keyfilePath).mode & 0o777), 0o600);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: --no-remove-source preserves the source key file', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, {
      handle: 'eth:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      removeSource: false,
      kdfParams: TEST_KDF,
    });
    ok(existsSync(srcKey));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: accepts hex-encoded key file (with and without 0x)', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const hex = priv(7).toString('hex');
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, '0x' + hex + '\n', { encoding: 'utf8' });
    const result = portalAdd(paths, {
      handle: 'eth:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      removeSource: false,
      kdfParams: TEST_KDF,
    });
    equal(result.address, addressFromPrivateKey(priv(7)));

    const srcKey2 = join(home, 'src2.key');
    writeFileSync(srcKey2, hex, { encoding: 'utf8' });
    const result2 = portalAdd(paths, {
      handle: 'eth:bot2',
      keyFile: srcKey2,
      passphrase: Buffer.from('p'),
      removeSource: false,
      kdfParams: TEST_KDF,
    });
    equal(result2.address, addressFromPrivateKey(priv(7)));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: rejects malformed key file', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const bad = join(home, 'bad.key');
    writeFileSync(bad, 'this is not a key');
    throws(() => portalAdd(paths, {
      handle: 'eth:bot', keyFile: bad, passphrase: Buffer.from('p'),
    }), /32 raw bytes or 64 hex/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: rejects invalid handle', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    throws(() => portalAdd(paths, {
      handle: 'bogus', keyFile: srcKey, passphrase: Buffer.from('p'),
    }));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: refuses to overwrite an existing portal', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, {
      handle: 'eth:bot', keyFile: srcKey, passphrase: Buffer.from('p'), removeSource: false,
      kdfParams: TEST_KDF,
    });
    throws(() => portalAdd(paths, {
      handle: 'eth:bot', keyFile: srcKey, passphrase: Buffer.from('p'),
    }), /already exists/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: stored keyfile decrypts to the original private key', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(42));
    const { keyfilePath } = portalAdd(paths, {
      handle: 'eth:bot', keyFile: srcKey, passphrase: Buffer.from('hunter2'), kdfParams: TEST_KDF,
    });
    const blob = readFileSync(keyfilePath);
    const sb = unsealKey(blob, Buffer.from('hunter2'));
    try {
      deepEqual(Array.from(sb.bytes()), Array.from(priv(42)));
    } finally { sb.dispose(); }
  } finally {
    rmSync(home, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// portalListFromDisk
// ---------------------------------------------------------------------------

test('portalListFromDisk: empty when no keys dir exists', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    deepEqual(portalListFromDisk(paths, Buffer.from('p')), []);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalListFromDisk: returns each portal with derived address, sorted', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const pass = Buffer.from('p');
    const keys: [string, number][] = [['eth:zzz', 1], ['eth:aaa', 2], ['eth:mmm', 3]];
    for (const [handle, byte] of keys) {
      const srcKey = join(home, `src-${byte}.key`);
      writeFileSync(srcKey, priv(byte));
      portalAdd(paths, { handle, keyFile: srcKey, passphrase: pass, kdfParams: TEST_KDF });
    }
    const list = portalListFromDisk(paths, pass);
    deepEqual(list.map((p) => p.handle), ['eth:aaa', 'eth:mmm', 'eth:zzz']);
    equal(list.find((p) => p.handle === 'eth:zzz')!.address, addressFromPrivateKey(priv(1)));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalListFromDisk: throws if any keyfile fails to decrypt', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, { handle: 'eth:bot', keyFile: srcKey, passphrase: Buffer.from('correct'), kdfParams: TEST_KDF });
    throws(() => portalListFromDisk(paths, Buffer.from('wrong')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// portalRemove
// ---------------------------------------------------------------------------

test('portalRemove: removes an existing portal', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const { keyfilePath } = portalAdd(paths, {
      handle: 'eth:bot', keyFile: srcKey, passphrase: Buffer.from('p'), kdfParams: TEST_KDF,
    });
    const result = portalRemove(paths, 'eth:bot');
    equal(result.removed, true);
    equal(existsSync(keyfilePath), false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalRemove: reports not-removed for absent portal', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const result = portalRemove(paths, 'eth:absent');
    equal(result.removed, false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalRemove: rejects malformed handle', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(() => portalRemove(paths, 'not-a-handle'));
  } finally {
    rmSync(home, { recursive: true });
  }
});
