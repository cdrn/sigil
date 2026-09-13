import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { scanBashCommand, stripInertText } from '../../src/hooks/command-scanner.js';

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

// ---------------------------------------------------------------------------
// #92 — message text is carved out only when the WHOLE command is one
// git/gh invocation; everything else is scanned exactly as before
// ---------------------------------------------------------------------------

const K = '~/.sigil/keys/a.sigil'; // a warded key path
const L = '~/.sigil/audit.log';

test('#92: git commit -F - with a quoted heredoc message is not a read', () => {
  const cmd = [
    "git commit -F - <<'EOF'",
    'fix(audit): harden the log',
    '',
    `so the old writer kept corrupting ${L}; see \`main:src/audit/log.ts\` | tail`,
    `and cat ${K} is mentioned here as prose`,
    'EOF',
  ].join('\n');
  equal(scanBashCommand(cmd).blocked, false);
  const carved = stripInertText(cmd);
  ok(carved.startsWith("git commit -F - <<'EOF'\n"));
  ok(carved.endsWith('\nEOF'));
  ok(!carved.includes('corrupting'));
  equal(carved.split('\n').length, cmd.split('\n').length);
});

test('#92: gh pr create --body-file - and git commit --file - also qualify; trailing newline ok', () => {
  equal(
    scanBashCommand(`gh pr create --title t --body-file - <<"EOF"\ncat ${K} | head\nEOF\n`).blocked,
    false,
  );
  equal(scanBashCommand(`git commit --amend --file - <<'MSG'\ntail ${K}\nMSG`).blocked, false);
  equal(
    scanBashCommand(`gh issue comment 3 --body-file - <<'EOF'\n$(cat ${K})\nEOF`).blocked,
    false,
    'quoted delimiter: no expansion',
  );
});

test('#92: inline message strings to git/gh are data', () => {
  equal(scanBashCommand(`git commit -m "corrupting ${L}; cat ${K} | head"`).blocked, false);
  equal(scanBashCommand(`git commit --message='cat ${K}; true' --no-verify`).blocked, false);
  equal(scanBashCommand(`gh pr create --title "x" --body "see ${L} | cat ${K}"`).blocked, false);
  equal(scanBashCommand(`gh issue comment 3 --body 'tail ${K}'`).blocked, false);
});

test('#92: a substitution inside a message string is still code', () => {
  ok(scanBashCommand(`git commit -m "$(cat ${K})"`).blocked);
  ok(scanBashCommand('git commit -m "key: `cat ' + K + '`"').blocked);
});

test('#92: any deviation from the exact shape leaves the command untouched for the normal scan', () => {
  const body = `\ncat ${K}\nEOF`;
  for (const cmd of [
    `bash <<'EOF'${body}`,
    `FOO=1 git commit -F - <<'EOF'${body}`,
    `git commit -F - <<'EOF' | bash${body}`,
    `git commit -F - <<'EOF'; bash x${body}`,
    `git commit -F - <<'EOF' > /tmp/x${body}`,
    `x=$(git commit -F - <<'EOF'${body}\n)`,
    `(git commit -F - <<'EOF'${body}\n)`,
    `git commit -F - <<EOF${body}`,
    `git commit -F - <<'EOF'X\ncat ${K}\nEOFX`,
    `git commit -F - <<'A' <<'B'${body}\nB`,
    `git commit -F - <<'EOF'\ncat ${K}\nEOF-not`,
    `cat > /tmp/msg.txt <<'EOF'${body}\ngit commit -F /tmp/msg.txt`,
    `tee /tmp/s <<'EOF'${body}\nbash /tmp/s`,
    `git status; git commit -m "cat ${K}"`,
    `git commit -m "cat ${K}" | cat`,
    `git -c alias.x='!cat ${K}' x`,
    `git -c gpg.program='cat ${K}' commit -m 'x'`,
    `git commit -m "$(cat ${K})"`,
    `echo "$(true; cat ${K})"`,
    `bash -c 'true; cat ${K}; true'`,
    // review round 4: an earlier terminator line ends the heredoc; what
    // follows it is a command, not message text
    `git version -F - <<'EOF'\nmessage\nEOF\ntrue; cat ${K}\nEOF`,
    // review round 4: a newline is a statement separator, never an
    // argument separator — the message would go to sh, not git
    `git --version\nsh -s -- -F - <<'EOF'\ntrue; cat ${K}\nEOF`,
    `git --version\necho -m 'true; cat ${K}'`,
    `echo -m 'true; cat ${K}'`,
    `gitx -m 'true; cat ${K}'`,
  ]) {
    equal(stripInertText(cmd), cmd, `untouched: ${cmd}`);
  }
});

test('#92: what the unchanged scanner refused, it still refuses', () => {
  for (const cmd of [
    `echo "$(true; cat ${K})"`,
    `bash -c 'true; cat ${K}; true'`,
    `cat > /tmp/msg.txt <<'EOF'\ncat ${K}\nEOF\ngit commit -F /tmp/msg.txt`, // use -F - instead
    `git commit -m "$(cat ${K})"`,
    `cat ${K}`,
    `true; cat ${K}`,
    `git version -F - <<'EOF'\nmessage\nEOF\ntrue; cat ${K}\nEOF`,
    `git --version\nsh -s -- -F - <<'EOF'\ntrue; cat ${K}\nEOF`,
    `echo -m 'true; cat ${K}'`,
  ]) {
    ok(scanBashCommand(cmd).blocked, cmd);
  }
});

test('#92: shapes main allowed are still allowed (unchanged scanner)', () => {
  equal(scanBashCommand(`echo 'cat ${K}'`).blocked, false);
  equal(scanBashCommand(`printf "%s\\n" ${K}`).blocked, false);
  equal(scanBashCommand(`command echo 'cat ${K}'`).blocked, false);
});
