import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { scanBashCommand } from '../../src/hooks/command-scanner.js';

test('blocks cat of a .key file argument', () => {
  ok(scanBashCommand('cat /etc/ssl/private.key').blocked);
});

test('does NOT block cat of .env (no longer on the wardlist)', () => {
  equal(scanBashCommand('cat ./.env').blocked, false);
  equal(scanBashCommand('cat /repo/.env.local').blocked, false);
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
  ok(scanBashCommand('echo hi && cat ~/.ssh/id_rsa').blocked);
  ok(scanBashCommand('true; cat /etc/pki/private.key').blocked);
});

test('first token (program name) is never matched as a path', () => {
  // If the program itself is a .pem (weird but possible), don't block.
  equal(scanBashCommand('./tool.pem --check').blocked, false);
});

// ---------------------------------------------------------------------------
// Reader-vs-recorder model (issue #45)
// ---------------------------------------------------------------------------

test('non-reader programs do not have their args path-scanned', () => {
  // git commit -F writes the file as a commit message; the path is data,
  // not a read target.
  equal(scanBashCommand('git commit -F /etc/ssl/private.key').blocked, false);
  // gh pr create --body-file likewise records the file as PR body text.
  equal(scanBashCommand('gh pr create --body-file ~/.ssh/id_rsa').blocked, false);
  // echo treats its args as literal text.
  equal(scanBashCommand('echo ~/.ssh/id_rsa').blocked, false);
});

test('reader programs invoked through an absolute path are still recognised', () => {
  ok(scanBashCommand('/usr/bin/cat ~/.ssh/id_rsa').blocked);
  ok(scanBashCommand('/bin/grep secret /etc/ssl/private.key').blocked);
});

test('subshell-substituted reads are still blocked because $( starts a new statement', () => {
  // `git commit` itself is not a reader, but the inner cat is — the
  // statement split on $( surfaces cat as the program of its own statement.
  ok(scanBashCommand('git commit -m "$(cat ~/.ssh/id_rsa)"').blocked);
  ok(scanBashCommand('echo `cat /etc/ssl/private.key`').blocked);
});

test('reader allowlist covers grep, head, tail, less, xxd, find', () => {
  ok(scanBashCommand('grep secret /etc/ssl/private.key').blocked);
  ok(scanBashCommand('head -n1 ~/.ssh/id_ed25519').blocked);
  ok(scanBashCommand('tail -f /tmp/foo.key').blocked);
  ok(scanBashCommand('less ~/.sigil/keys/eth:bot.sigil').blocked);
  ok(scanBashCommand('xxd /etc/ssl/private.key').blocked);
  ok(scanBashCommand('find . -name id_rsa -exec cat ~/.ssh/id_rsa \\;').blocked);
});

test('build / runtime tools never path-scan their args', () => {
  equal(scanBashCommand('node ./tool.key').blocked, false);
  equal(scanBashCommand('npm install ./pkg.key').blocked, false);
  equal(scanBashCommand('tsc -p ./tsconfig.key').blocked, false);
});
