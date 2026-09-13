import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { scanBashCommand, splitStatements } from '../../src/hooks/command-scanner.js';

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
// #92 — literal mentions of warded paths are not reads
// ---------------------------------------------------------------------------

const K = '~/.sigil/keys/a.sigil'; // a warded key path
const L = '~/.sigil/audit.log';

test('#92: a commit message heredoc that mentions a warded path is not a read', () => {
  const cmd = [
    "cat > /tmp/msg.txt <<'EOF'",
    'fix(audit): harden the log',
    '',
    `so the old writer kept corrupting ${L}; see \`main:src/audit/log.ts\` | tail`,
    `and cat ${K} is mentioned here as prose`,
    'EOF',
    'git commit -F /tmp/msg.txt',
  ].join('\n');
  equal(scanBashCommand(cmd).blocked, false);
});

test('#92: -m "…" prose with separators and a warded path is not a read', () => {
  equal(scanBashCommand(`git commit -m "corrupting ${L}; cat ${K} | head"`).blocked, false);
  equal(scanBashCommand(`echo 'cat ${K}'`).blocked, false);
  equal(scanBashCommand(`printf "%s\\n" ${K}`).blocked, false, 'printf is not a reader');
});

test('#92: substitutions still execute inside double quotes and unquoted heredocs → blocked', () => {
  ok(scanBashCommand(`echo "$(cat ${K})"`).blocked);
  ok(scanBashCommand(`git commit -m "key: \`cat ${K}\`"`).blocked);
  ok(scanBashCommand(`cat <<EOF\nhere: $(head -c 32 ${K})\nEOF`).blocked);
  ok(scanBashCommand(`cat <<EOF\n\`cat ${K}\`\nEOF`).blocked);
});

test('#92: single-quoted substitutions are literal → not blocked', () => {
  equal(scanBashCommand(`echo '$(cat ${K})'`).blocked, false);
  equal(scanBashCommand(`echo '\`cat ${K}\`'`).blocked, false);
});

test('#92: a quoted-delimiter heredoc body is literal even when it looks like a read', () => {
  equal(scanBashCommand(`cat <<'EOF'\ncat ${K}\n$(cat ${K})\nEOF`).blocked, false);
  equal(scanBashCommand(`cat <<"EOF"\ncat ${K}\nEOF`).blocked, false);
});

test('#92: real reads on other lines / after separators are still blocked', () => {
  ok(scanBashCommand(`echo hi\ncat ${K}`).blocked);
  ok(scanBashCommand(`echo hi; cat ${K}`).blocked);
  ok(scanBashCommand(`echo hi && cat ${K}`).blocked);
  ok(scanBashCommand(`true || tail ${K}`).blocked);
  ok(scanBashCommand(`ls | grep x ${K}`).blocked);
  ok(scanBashCommand(`cat <<'EOF' > /tmp/x\nbody\nEOF\ncat ${K}`).blocked, 'read after a heredoc');
});

test('#92: heredoc command line itself is still scanned (operands before/after <<)', () => {
  ok(scanBashCommand(`cat ${K} <<'EOF'\nbody\nEOF`).blocked);
  ok(scanBashCommand(`cat <<'EOF' ${K}\nbody\nEOF`).blocked, 'operand after the delimiter');
});

test('#92: splitStatements — quoting and heredoc semantics', () => {
  const s = (c: string) => splitStatements(c).map((x) => x.trim());
  equal(JSON.stringify(s('a; b | c && d\ne')), JSON.stringify(['a', 'b', 'c', 'd', 'e']));
  equal(JSON.stringify(s('a "x; y | z" b')), JSON.stringify(['a "x; y | z" b']));
  equal(JSON.stringify(s("a '$(x)' b")), JSON.stringify(["a '$(x)' b"]));
  equal(JSON.stringify(s('a "$(x)" b')), JSON.stringify(['a "', 'x)" b']));
  equal(
    JSON.stringify(s("cat <<'EOF'\nline; one | two\nEOF\nnext")),
    JSON.stringify(['cat', 'next']),
  );
  equal(
    JSON.stringify(s('cat <<EOF\nplain $(sub one) `sub two`\nEOF')),
    JSON.stringify(['cat', 'sub one', 'sub two']),
  );
  equal(JSON.stringify(s('cat <<-EOF\n\tbody\n\tEOF\nafter')), JSON.stringify(['cat', 'after']));
});
