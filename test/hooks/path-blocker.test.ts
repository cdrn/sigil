import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { homedir } from 'node:os';
import { isBlockedPath } from '../../src/hooks/path-blocker.js';

test('blocks ~/.sigil/**', () => {
  const d = isBlockedPath(`${homedir()}/.sigil/keys/eth:bot.sigil`);
  ok(d.blocked);
});

test('blocks *.pem at any depth', () => {
  ok(isBlockedPath('/some/where/secret.pem').blocked);
  ok(isBlockedPath('secret.pem').blocked);
  ok(isBlockedPath('./secret.pem').blocked);
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

test('blocks .env and .env.* at any depth', () => {
  ok(isBlockedPath('/repo/.env').blocked);
  ok(isBlockedPath('/repo/.env.local').blocked);
  ok(isBlockedPath('.env').blocked);
  ok(isBlockedPath('./.env.production').blocked);
});

test('blocks ethereum keystore dirs', () => {
  ok(isBlockedPath('/data/keystore/UTC--2020-01-01--addr').blocked);
  ok(isBlockedPath('keystore').blocked);
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
  equal(
    isBlockedPath('/foo/public/db.yaml', { extraPatterns: ['**/secrets/**'] }).blocked,
    false,
  );
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
