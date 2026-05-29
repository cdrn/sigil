import { test } from 'node:test';
import { deepEqual, equal, ok, throws } from 'node:assert/strict';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SecretBuffer, sealKey } from '../../src/crypto/index.js';
import { addressFromPrivateKey } from '../../src/eth/address.js';
import { HandleLoadError, HandleTable } from '../../src/daemon/handles.js';

// Fast KDF for tests.
const TEST_KDF = { m: 256, t: 1, p: 1 };

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-handles-'));
}

function priv(byte: number): Buffer {
  const p = Buffer.alloc(32); p[31] = byte; return p;
}

// ---------------------------------------------------------------------------
// parseHandle
// ---------------------------------------------------------------------------

test('parseHandle accepts well-formed evm handles', () => {
  deepEqual(HandleTable.parseHandle('evm:bot'), { kind: 'evm', name: 'bot' });
  deepEqual(HandleTable.parseHandle('evm:executor_01'), { kind: 'evm', name: 'executor_01' });
  deepEqual(HandleTable.parseHandle('evm:Bot-2'), { kind: 'evm', name: 'Bot-2' });
});

test('parseHandle rejects malformed handles', () => {
  throws(() => HandleTable.parseHandle('evm'), HandleLoadError); // no name
  throws(() => HandleTable.parseHandle('evm:'), HandleLoadError);
  throws(() => HandleTable.parseHandle('eth:bot'), HandleLoadError); // legacy prefix rejected post-migration
  throws(() => HandleTable.parseHandle(':bot'), HandleLoadError);
  throws(() => HandleTable.parseHandle('evm:bot/x'), HandleLoadError);
  throws(() => HandleTable.parseHandle('evm:bot.key'), HandleLoadError);
  throws(() => HandleTable.parseHandle('btc:bot'), HandleLoadError); // unknown kind
});

test('handleFromFilename extracts handle from .sigil filenames', () => {
  equal(HandleTable.handleFromFilename('evm:bot.sigil'), 'evm:bot');
  equal(HandleTable.handleFromFilename('not-a-handle.sigil'), null);
  equal(HandleTable.handleFromFilename('evm:bot.txt'), null);
  equal(HandleTable.handleFromFilename('foo.sigil'), null);
});

// ---------------------------------------------------------------------------
// addEntry / get / list / dispose
// ---------------------------------------------------------------------------

test('addEntry stores a key and exposes handle + derived address', () => {
  const t = new HandleTable();
  t.addEntry('evm:bot', new SecretBuffer(priv(1)));
  ok(t.has('evm:bot'));
  const list = t.list();
  equal(list.length, 1);
  equal(list[0]!.handle, 'evm:bot');
  equal(list[0]!.kind, 'evm');
  equal(list[0]!.address, addressFromPrivateKey(priv(1)));
  t.dispose();
});

test('addEntry rejects duplicate handle and disposes the rejected secret', () => {
  const t = new HandleTable();
  t.addEntry('evm:bot', new SecretBuffer(priv(1)));
  const dup = new SecretBuffer(priv(2));
  throws(() => t.addEntry('evm:bot', dup), HandleLoadError);
  // The duplicate's secret should have been disposed by addEntry.
  ok(dup.isDisposed, 'rejected secret should be disposed');
  t.dispose();
});

test('addEntry rejects malformed handle', () => {
  const t = new HandleTable();
  throws(() => t.addEntry('not-a-handle', new SecretBuffer(priv(1))), HandleLoadError);
  t.dispose();
});

test('get returns the SecretBuffer for known handles, undefined for unknown', () => {
  const t = new HandleTable();
  t.addEntry('evm:bot', new SecretBuffer(priv(1)));
  ok(t.get('evm:bot') !== undefined);
  equal(t.get('evm:nope'), undefined);
  t.dispose();
});

test('dispose zeroizes every key and prevents further use', () => {
  const t = new HandleTable();
  const sb1 = new SecretBuffer(priv(1));
  const sb2 = new SecretBuffer(priv(2));
  t.addEntry('evm:a', sb1);
  t.addEntry('evm:b', sb2);
  t.dispose();
  ok(sb1.isDisposed && sb2.isDisposed);
  ok(t.isDisposed);
  throws(() => t.has('evm:a'), /disposed/);
  throws(() => t.list(), /disposed/);
  throws(() => t.get('evm:a'), /disposed/);
});

test('dispose is idempotent', () => {
  const t = new HandleTable();
  t.dispose();
  t.dispose(); // no throw
  ok(t.isDisposed);
});

// ---------------------------------------------------------------------------
// loadFromDir (filesystem)
// ---------------------------------------------------------------------------

test('loadFromDir on a missing dir is a no-op (genesis state)', () => {
  const t = new HandleTable();
  t.loadFromDir('/nonexistent/should/never/exist/abc123', Buffer.from('p'));
  equal(t.list().length, 0);
  t.dispose();
});

test('loadFromDir loads every well-formed keyfile', () => {
  const dir = mkTmp();
  try {
    const passphrase = Buffer.from('test-pass');
    writeFileSync(join(dir, 'evm:bot.sigil'), sealKey(priv(1), passphrase, TEST_KDF));
    writeFileSync(join(dir, 'evm:executor.sigil'), sealKey(priv(2), passphrase, TEST_KDF));
    // Non-keyfile should be ignored.
    writeFileSync(join(dir, 'README.txt'), 'ignore me');

    const t = new HandleTable();
    t.loadFromDir(dir, passphrase);
    const list = t.list();
    equal(list.length, 2);
    deepEqual(list.map((p) => p.handle).sort(), ['evm:bot', 'evm:executor']);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadFromDir is deterministic in order (sorted by filename)', () => {
  const dir = mkTmp();
  try {
    const passphrase = Buffer.from('p');
    // Write in a non-sorted order.
    writeFileSync(join(dir, 'evm:zzz.sigil'), sealKey(priv(1), passphrase, TEST_KDF));
    writeFileSync(join(dir, 'evm:aaa.sigil'), sealKey(priv(2), passphrase, TEST_KDF));
    writeFileSync(join(dir, 'evm:mmm.sigil'), sealKey(priv(3), passphrase, TEST_KDF));

    const t = new HandleTable();
    t.loadFromDir(dir, passphrase);
    deepEqual(
      t.list().map((p) => p.handle),
      ['evm:aaa', 'evm:mmm', 'evm:zzz'],
    );
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadFromDir throws HandleLoadError on wrong passphrase', () => {
  const dir = mkTmp();
  try {
    writeFileSync(
      join(dir, 'evm:bot.sigil'),
      sealKey(priv(1), Buffer.from('right'), TEST_KDF),
    );
    const t = new HandleTable();
    throws(() => t.loadFromDir(dir, Buffer.from('wrong')), /wrong passphrase|tampered/);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadFromDir on tampered keyfile throws HandleLoadError', () => {
  const dir = mkTmp();
  try {
    const passphrase = Buffer.from('p');
    const blob = sealKey(priv(1), passphrase, TEST_KDF);
    blob[blob.length - 1] = (blob[blob.length - 1] ?? 0) ^ 0xff;
    writeFileSync(join(dir, 'evm:bot.sigil'), blob);
    const t = new HandleTable();
    throws(() => t.loadFromDir(dir, passphrase), /wrong passphrase|tampered/);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadFromDir on subdir of files (nested) ignores nested entries', () => {
  const dir = mkTmp();
  try {
    const passphrase = Buffer.from('p');
    mkdirSync(join(dir, 'subdir'));
    writeFileSync(
      join(dir, 'subdir', 'evm:nested.sigil'),
      sealKey(priv(7), passphrase, TEST_KDF),
    );
    writeFileSync(join(dir, 'evm:bot.sigil'), sealKey(priv(1), passphrase, TEST_KDF));
    const t = new HandleTable();
    t.loadFromDir(dir, passphrase);
    deepEqual(t.list().map((p) => p.handle), ['evm:bot']);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// lock / unlock state
// ---------------------------------------------------------------------------

test('fresh table reports isUnlocked() === false', () => {
  const t = new HandleTable();
  equal(t.isUnlocked(), false);
  t.dispose();
});

test('addEntry alone does NOT flip unlocked (only markUnlocked / loadFromDir does)', () => {
  const t = new HandleTable();
  t.addEntry('evm:bot', new SecretBuffer(priv(1)));
  equal(t.isUnlocked(), false);
  t.markUnlocked();
  equal(t.isUnlocked(), true);
  t.dispose();
});

test('loadFromDir on empty/missing dir marks the table unlocked anyway', () => {
  const t = new HandleTable();
  t.loadFromDir('/nonexistent/abc123', Buffer.from('p'));
  equal(t.isUnlocked(), true);
  equal(t.list().length, 0);
  t.dispose();
});

test('loadFromDir on populated dir marks the table unlocked', () => {
  const dir = mkTmp();
  try {
    const passphrase = Buffer.from('p');
    writeFileSync(join(dir, 'evm:bot.sigil'), sealKey(priv(1), passphrase, TEST_KDF));
    const t = new HandleTable();
    t.loadFromDir(dir, passphrase);
    equal(t.isUnlocked(), true);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('loadFromDir failure leaves table locked + entries zeroized', () => {
  const dir = mkTmp();
  try {
    writeFileSync(
      join(dir, 'evm:bot.sigil'),
      sealKey(priv(1), Buffer.from('right'), TEST_KDF),
    );
    const t = new HandleTable();
    throws(() => t.loadFromDir(dir, Buffer.from('wrong')), /wrong passphrase|tampered/);
    equal(t.isUnlocked(), false);
    equal(t.list().length, 0);
    t.dispose();
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('lock() zeroizes entries, clears them, and re-locks', () => {
  const t = new HandleTable();
  const sb = new SecretBuffer(priv(1));
  t.addEntry('evm:bot', sb);
  t.markUnlocked();
  ok(t.isUnlocked());
  equal(t.list().length, 1);

  t.lock();
  equal(t.isUnlocked(), false);
  equal(t.list().length, 0);
  ok(sb.isDisposed);

  // Table is still usable — can be re-unlocked.
  const sb2 = new SecretBuffer(priv(2));
  t.addEntry('evm:bot', sb2);
  t.markUnlocked();
  equal(t.isUnlocked(), true);
  equal(t.list().length, 1);
  t.dispose();
});

test('lock() is idempotent on an empty / already-locked table', () => {
  const t = new HandleTable();
  t.lock(); // no entries, no-op
  t.lock(); // still no-op
  equal(t.isUnlocked(), false);
  t.dispose();
});

test('isUnlocked() returns false after dispose()', () => {
  const t = new HandleTable();
  t.markUnlocked();
  ok(t.isUnlocked());
  t.dispose();
  equal(t.isUnlocked(), false);
});

test('markUnlocked / lock / loadFromDir / addEntry throw after dispose', () => {
  const t = new HandleTable();
  t.dispose();
  throws(() => t.markUnlocked(), /disposed/);
  // lock() is intentionally a silent no-op after dispose (idempotent).
  t.lock();
  throws(() => t.loadFromDir('/tmp', Buffer.from('p')), /disposed/);
  throws(() => t.addEntry('evm:x', new SecretBuffer(priv(1))), /disposed/);
});
