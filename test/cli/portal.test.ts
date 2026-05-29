import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { unsealKey } from '../../src/crypto/index.js';
import { addressFromPrivateKey } from '../../src/eth/index.js';
import { resolvePaths } from '../../src/cli/paths.js';
import { policyInit, portalAdd, portalAddress, portalListFromDisk, portalNew, portalRemove } from '../../src/cli/portal.js';
import { parsePolicy } from '../../src/policy/index.js';

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
      handle: 'evm:bot',
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
      handle: 'evm:bot',
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
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      removeSource: false,
      kdfParams: TEST_KDF,
    });
    equal(result.address, addressFromPrivateKey(priv(7)));

    const srcKey2 = join(home, 'src2.key');
    writeFileSync(srcKey2, hex, { encoding: 'utf8' });
    const result2 = portalAdd(paths, {
      handle: 'evm:bot2',
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
      handle: 'evm:bot', keyFile: bad, passphrase: Buffer.from('p'),
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
      handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'), removeSource: false,
      kdfParams: TEST_KDF,
    });
    throws(() => portalAdd(paths, {
      handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'),
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
      handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('hunter2'), kdfParams: TEST_KDF,
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
    const keys: [string, number][] = [['evm:zzz', 1], ['evm:aaa', 2], ['evm:mmm', 3]];
    for (const [handle, byte] of keys) {
      const srcKey = join(home, `src-${byte}.key`);
      writeFileSync(srcKey, priv(byte));
      portalAdd(paths, { handle, keyFile: srcKey, passphrase: pass, kdfParams: TEST_KDF });
    }
    const list = portalListFromDisk(paths, pass);
    deepEqual(list.map((p) => p.handle), ['evm:aaa', 'evm:mmm', 'evm:zzz']);
    equal(list.find((p) => p.handle === 'evm:zzz')!.address, addressFromPrivateKey(priv(1)));
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
    portalAdd(paths, { handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('correct'), kdfParams: TEST_KDF });
    throws(() => portalListFromDisk(paths, Buffer.from('wrong')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// portalRemove
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// portalAddress (for `sigil portal qr`)
// ---------------------------------------------------------------------------

test('portalAddress: decrypts a single keyfile and returns its derived address', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(7));
    portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    const addr = portalAddress(paths, 'evm:bot', Buffer.from('p'));
    equal(addr, addressFromPrivateKey(priv(7)));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAddress: rejects malformed handle', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(() => portalAddress(paths, 'not-a-handle', Buffer.from('p')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAddress: errors helpfully when keyfile is missing', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(
      () => portalAddress(paths, 'evm:absent', Buffer.from('p')),
      /portal "evm:absent" not found/,
    );
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAddress: wrong passphrase throws (does NOT return a junk address)', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('correct'),
      kdfParams: TEST_KDF,
    });
    throws(() => portalAddress(paths, 'evm:bot', Buffer.from('wrong')));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalRemove: removes an existing portal', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const { keyfilePath } = portalAdd(paths, {
      handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'), kdfParams: TEST_KDF,
    });
    const result = portalRemove(paths, 'evm:bot');
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
    const result = portalRemove(paths, 'evm:absent');
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

// ---------------------------------------------------------------------------
// Policy file integration
// ---------------------------------------------------------------------------

test('portalAdd: writes a permissive policy file by default', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const result = portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    ok(existsSync(result.policyPath));
    const source = readFileSync(result.policyPath, 'utf8');
    ok(/mode = "permissive"/.test(source));
    // 0o600 because the policy describes what this key can do
    equal((statSync(result.policyPath).mode & 0o777), 0o600);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: --strict policyMode writes the strict template', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const result = portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
      policyMode: 'strict',
    });
    const source = readFileSync(result.policyPath, 'utf8');
    ok(/mode = "strict"/.test(source));
    // Sanity: it includes the commented examples
    ok(/ERC-20 transfer/.test(source));
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalAdd: refuses if a policy file already exists at the target path', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    // Pre-plant a policy file at the target path.
    mkdirSync(paths.policyDir, { recursive: true });
    writeFileSync(join(paths.policyDir, 'evm:bot.toml'), '# pre-existing');
    throws(() => portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    }), /policy file.*already exists/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalRemove: removes the policy file alongside the keyfile', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    const added = portalAdd(paths, {
      handle: 'evm:bot',
      keyFile: srcKey,
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    ok(existsSync(added.keyfilePath));
    ok(existsSync(added.policyPath));
    portalRemove(paths, 'evm:bot');
    equal(existsSync(added.keyfilePath), false);
    equal(existsSync(added.policyPath), false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('policyInit: writes a permissive policy file for an existing portal', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, { handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'), kdfParams: TEST_KDF });
    // Wipe the policy file as if it never existed (older sigil version).
    rmSync(join(paths.policyDir, 'evm:bot.toml'));

    const result = policyInit(paths, 'evm:bot', 'permissive');
    ok(existsSync(result.policyPath));
    const parsed = parsePolicy(readFileSync(result.policyPath, 'utf8'));
    equal(parsed.mode, 'permissive');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('policyInit: --strict template parses and denies by default', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, { handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'), kdfParams: TEST_KDF });
    rmSync(join(paths.policyDir, 'evm:bot.toml'));

    policyInit(paths, 'evm:bot', 'strict');
    const parsed = parsePolicy(readFileSync(join(paths.policyDir, 'evm:bot.toml'), 'utf8'));
    equal(parsed.mode, 'strict');
    // Strict template defaults — empty allow_to, zero cap, signing disabled.
    deepEqual(parsed.allowTo, []);
    equal(parsed.maxValueWei, 0n);
    equal(parsed.allowMessageSigning, false);
    equal(parsed.allowTypedData, false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('policyInit: refuses to clobber an existing policy file', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const srcKey = join(home, 'src.key');
    writeFileSync(srcKey, priv(1));
    portalAdd(paths, { handle: 'evm:bot', keyFile: srcKey, passphrase: Buffer.from('p'), kdfParams: TEST_KDF });
    // policy file is already there from portalAdd.
    throws(() => policyInit(paths, 'evm:bot', 'permissive'), /policy already exists/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('policyInit: refuses if the portal keyfile does not exist', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(() => policyInit(paths, 'evm:absent', 'permissive'), /portal "evm:absent" not found/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: writes encrypted keyfile + policy and returns a valid address', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const r = portalNew(paths, {
      handle: 'evm:fresh',
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    ok(/^0x[0-9a-f]{40}$/.test(r.address));
    ok(existsSync(r.keyfilePath));
    ok(existsSync(r.policyPath));
    equal(statSync(r.keyfilePath).mode & 0o777, 0o600);
    equal(statSync(r.policyPath).mode & 0o777, 0o600);
    // Default policy is permissive.
    const policy = parsePolicy(readFileSync(r.policyPath, 'utf8'));
    equal(policy.mode, 'permissive');
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: --strict writes a locked-down template', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const r = portalNew(paths, {
      handle: 'evm:cold',
      passphrase: Buffer.from('p'),
      policyMode: 'strict',
      kdfParams: TEST_KDF,
    });
    const policy = parsePolicy(readFileSync(r.policyPath, 'utf8'));
    equal(policy.mode, 'strict');
    equal(policy.allowMessageSigning, false);
    equal(policy.allowTypedData, false);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: distinct calls produce distinct addresses (sampling-based)', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const addrs = new Set<string>();
    for (let i = 0; i < 10; i++) {
      const r = portalNew(paths, {
        handle: `evm:k${i}`,
        passphrase: Buffer.from('p'),
        kdfParams: TEST_KDF,
      });
      addrs.add(r.address);
    }
    // Astronomically unlikely to collide; if it does we have bigger problems.
    equal(addrs.size, 10);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: encrypted keyfile decrypts back to a working private key', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    const r = portalNew(paths, {
      handle: 'evm:test',
      passphrase: Buffer.from('passpass'),
      kdfParams: TEST_KDF,
    });
    // Decrypt with the same passphrase, derive address, confirm it matches.
    const blob = readFileSync(r.keyfilePath);
    const sb = unsealKey(blob, Buffer.from('passpass'));
    try {
      equal(addressFromPrivateKey(sb.bytes()), r.address);
    } finally {
      sb.dispose();
    }
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: refuses if portal already exists', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    portalNew(paths, {
      handle: 'evm:bot',
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    });
    throws(() => portalNew(paths, {
      handle: 'evm:bot',
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    }), /portal "evm:bot" already exists/);
  } finally {
    rmSync(home, { recursive: true });
  }
});

test('portalNew: refuses invalid handle format', () => {
  const home = mkTmpHome();
  try {
    const paths = resolvePaths({ SIGIL_HOME: home });
    throws(() => portalNew(paths, {
      handle: 'no-colon',
      passphrase: Buffer.from('p'),
      kdfParams: TEST_KDF,
    }));
  } finally {
    rmSync(home, { recursive: true });
  }
});
