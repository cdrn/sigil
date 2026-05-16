import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { scanBashCommand } from '../../src/hooks/command-scanner.js';

test('blocks cat of a .key file argument', () => {
  ok(scanBashCommand('cat /etc/ssl/private.key').blocked);
});

test('blocks cat of .env at any depth', () => {
  ok(scanBashCommand('cat ./.env').blocked);
  ok(scanBashCommand('cat /repo/.env.local').blocked);
});

test('blocks reads from ~/.sigil/**', () => {
  ok(scanBashCommand('cat ~/.sigil/keys/eth:bot.sigil').blocked);
});

test('blocks even with shell quoting around the path', () => {
  ok(scanBashCommand('cat "~/.ssh/id_rsa"').blocked);
  ok(scanBashCommand("cat '~/.ssh/id_ed25519'").blocked);
});

test('blocks gpg --export-secret-keys regardless of args', () => {
  ok(scanBashCommand('gpg --export-secret-keys --armor MYKEYID').blocked);
  ok(scanBashCommand('gpg --export-secret-key alice@example.com').blocked);
});

test('blocks ssh-keygen -y on a private key', () => {
  ok(scanBashCommand('ssh-keygen -y -f mykey').blocked);
});

test('blocks openssl key dump', () => {
  ok(scanBashCommand('openssl pkey -in private.pem -noout -text').blocked);
});

test('does NOT block ordinary commands', () => {
  equal(scanBashCommand('ls -la').blocked, false);
  equal(scanBashCommand('npm install').blocked, false);
  equal(scanBashCommand('echo hello world').blocked, false);
  equal(scanBashCommand('git status').blocked, false);
  equal(scanBashCommand('node dist/src/bin/sigild.js').blocked, false);
});

test('still blocks across compound statements', () => {
  ok(scanBashCommand('echo hi && cat .env').blocked);
  ok(scanBashCommand('true; cat /etc/pki/private.key').blocked);
});

test('first token (program name) is never matched as a path', () => {
  // If the program itself is a .pem (weird but possible), don't block.
  equal(scanBashCommand('./tool.pem --check').blocked, false);
});
