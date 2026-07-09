import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { homedir } from 'node:os';
import { DEFAULT_PATH_PATTERNS, isBlockedPath } from '../../src/hooks/path-blocker.js';

// Pin the exact built-in set. This is the source of truth THREAT_MODEL.md
// describes in prose; if you change the blocker, update this AND the doc in
// the same commit — the two silently diverging is precisely the bug this
// test exists to prevent (a documented block that isn't implemented is worse
// than no claim, because users rely on it).
test('DEFAULT_PATH_PATTERNS is exactly the documented whole-file key-store set', () => {
  deepEqual(
    [...DEFAULT_PATH_PATTERNS],
    [
      '**/.sigil/**',
      '**/*.key',
      '**/*.keystore',
      '**/*.jks',
      '**/*.p12',
      '**/.ssh/id_*',
      '**/.ssh/*_rsa',
      '**/.ssh/*_ed25519',
      '**/.ssh/*_ecdsa',
      '**/.gnupg/**',
      '**/.password-store/**',
    ],
  );
});

test('blocks ~/.sigil/**', () => {
  const d = isBlockedPath(`${homedir()}/.sigil/keys/evm:bot.sigil`);
  ok(d.blocked);
});

test('blocks *.key, *.keystore, *.jks, *.p12', () => {
  ok(isBlockedPath('/x/y/private.key').blocked);
  ok(isBlockedPath('wallet.keystore').blocked);
  ok(isBlockedPath('/etc/secrets/store.jks').blocked);
  ok(isBlockedPath('certs/identity.p12').blocked);
});

test('blocks SSH private key conventions', () => {
  ok(isBlockedPath(`${homedir()}/.ssh/id_rsa`).blocked);
  ok(isBlockedPath(`${homedir()}/.ssh/id_ed25519`).blocked);
  ok(isBlockedPath(`${homedir()}/.ssh/bot_rsa`).blocked);
});

test('does NOT block *.pem (mostly public certs / CA bundles)', () => {
  equal(isBlockedPath('/some/where/cert.pem').blocked, false);
  equal(isBlockedPath('secret.pem').blocked, false);
  equal(isBlockedPath('./ca-bundle.pem').blocked, false);
});

test('does NOT block .env / .env.* (templates and examples dominate)', () => {
  equal(isBlockedPath('/repo/.env').blocked, false);
  equal(isBlockedPath('/repo/.env.local').blocked, false);
  equal(isBlockedPath('.env').blocked, false);
  equal(isBlockedPath('./.env.production').blocked, false);
});

test('does NOT block bare keystore/ dirs (too generic; *.keystore extension is enough)', () => {
  equal(isBlockedPath('/data/keystore/UTC--2020-01-01--addr').blocked, false);
  equal(isBlockedPath('keystore').blocked, false);
});

test('blocks GPG and pass(1) stores', () => {
  ok(isBlockedPath(`${homedir()}/.gnupg/private-keys-v1.d/abc.key`).blocked);
  ok(isBlockedPath(`${homedir()}/.password-store/work/api.gpg`).blocked);
});

test('does not block ordinary file paths', () => {
  equal(isBlockedPath('/etc/hostname').blocked, false);
  equal(isBlockedPath('package.json').blocked, false);
  equal(isBlockedPath('/usr/local/bin/node').blocked, false);
  equal(isBlockedPath('src/main.ts').blocked, false);
});

test('extra patterns are respected', () => {
  ok(isBlockedPath('/foo/secrets/db.yaml', { extraPatterns: ['**/secrets/**'] }).blocked);
  equal(isBlockedPath('/foo/public/db.yaml', { extraPatterns: ['**/secrets/**'] }).blocked, false);
});

test('matchedPattern is reported on block', () => {
  const d = isBlockedPath('/foo/private.key');
  ok(d.blocked);
  ok(d.matchedPattern && d.matchedPattern.includes('*.key'));
});

test('resolves .. lexically before matching', () => {
  // /a/../.sigil/x normalises to /.sigil/x, which matches **/.sigil/**.
  ok(isBlockedPath('/a/../.sigil/x').blocked);
});
