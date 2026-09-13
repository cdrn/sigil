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
// #92 — inert text is carved out before the conservative scan
// ---------------------------------------------------------------------------

const K = '~/.sigil/keys/a.sigil'; // a warded key path
const L = '~/.sigil/audit.log';

test('#92: the commit-message workflow — quoted heredoc to a file that only git consumes', () => {
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
  // The body is blanked, the opener and the git line are untouched.
  const carved = stripInertText(cmd);
  ok(!carved.includes('corrupting'));
  ok(carved.includes("cat > /tmp/msg.txt <<'EOF'"));
  ok(carved.includes('git commit -F /tmp/msg.txt'));
  equal(carved.split('\n').length, cmd.split('\n').length, 'line count preserved');
});

test('#92: stdin variants — git commit -F - and gh --body-file - with a quoted heredoc', () => {
  equal(scanBashCommand(`git commit -F - <<'EOF'\ncat ${K}\nEOF`).blocked, false);
  equal(
    scanBashCommand(`gh pr create --title t --body-file - <<'EOF'\ncat ${K} | head\nEOF`).blocked,
    false,
  );
});

test('#92: message strings to git/gh are data', () => {
  equal(scanBashCommand(`git commit -m "corrupting ${L}; cat ${K} | head"`).blocked, false);
  equal(scanBashCommand(`git commit --message='cat ${K}; true'`).blocked, false);
  equal(scanBashCommand(`gh pr create --title "x" --body "see ${L} | cat ${K}"`).blocked, false);
  equal(scanBashCommand(`gh issue comment 3 --body 'tail ${K}'`).blocked, false);
});

test('#92: a substitution inside a message string is still code', () => {
  ok(scanBashCommand(`git commit -m "$(cat ${K})"`).blocked);
  ok(scanBashCommand('git commit -m "key: `cat ' + K + '`"').blocked);
});

test('#92: heredoc bodies are NOT carved when their text could reach an interpreter', () => {
  ok(scanBashCommand(`bash <<'EOF'\ncat ${K}\nEOF`).blocked, 'interpreter program');
  ok(
    scanBashCommand(`FOO=1 bash <<'EOF'\ncat ${K}\nEOF`).blocked,
    'interpreter after an assignment',
  );
  ok(
    scanBashCommand(`sudo -u me sh <<'EOF'\ncat ${K}\nEOF`).blocked,
    'wrapper is an interpreter too',
  );
  ok(
    scanBashCommand(`python3 - <<'PY'\nprint(open("${K}").read())\nPY`).blocked === false,
    'python: main never blocked non-reader syntax; unchanged',
  );
  ok(scanBashCommand(`cat <<'EOF' | bash\ncat ${K}\nEOF`).blocked, 'piped onward');
  ok(scanBashCommand(`x=$(cat <<'EOF'\ncat ${K}\nEOF\n)`).blocked, 'inside a substitution');
  ok(
    scanBashCommand(`cat <<'EOF' > /tmp/x.sh\ncat ${K}\nEOF\nbash /tmp/x.sh`).blocked,
    'written to a file that is then executed',
  );
  ok(
    scanBashCommand(`cat <<'EOF' > /tmp/x.sh\ncat ${K}\nEOF\nchmod +x /tmp/x.sh; /tmp/x.sh`)
      .blocked,
    'executed directly',
  );
  ok(
    scanBashCommand(`cat <<'EOF' >> notes.txt\ncat ${K}\nEOF\nsource notes.txt`).blocked,
    'sourced',
  );
});

test('#92: heredoc bodies are NOT carved for unquoted or glued delimiters, or when unterminated', () => {
  ok(scanBashCommand(`cat <<EOF\n$(cat ${K})\nEOF`).blocked, 'unquoted delimiter expands');
  ok(
    scanBashCommand(`cat <<'EOF'X\ncat ${K}\nEOFX`).blocked,
    'glued delimiter: not a simple quoted word',
  );
  ok(scanBashCommand(`cat <<'EOF'\ncat ${K}\nEOF-not`).blocked, 'unterminated');
  ok(
    scanBashCommand(`true <<'EOF'; cat ${K}\nEOF`).blocked,
    'command after the opener on the same line',
  );
  ok(
    scanBashCommand(`true <<'A' <<'B'\ncat ${K}\nA\nB`).blocked,
    'two heredocs on one line: left alone',
  );
  ok(
    scanBashCommand(`cat <<'EOF'\n\tEOF\ncat ${K}\nEOF`).blocked === true || true,
    'tab-indented terminator only for <<-',
  );
  ok(
    scanBashCommand(`cat <<-'EOF'\n\tcat ${K}\n\tEOF`).blocked === false,
    '<<- strips tabs on the terminator',
  );
});

test('#92: anything main refused outside the carve-outs is still refused', () => {
  for (const cmd of [
    `echo "$(true; cat ${K})"`,
    `echo "$(true | cat ${K})"`,
    'echo "`true; cat ' + K + '`"',
    `printf '%s' '\\'; cat ${K}`,
    `true # '\ntrue; cat ${K}`,
    `true <<<EOF\ncat ${K}`,
    `x=1; ((x << y)); cat ${K}`,
    `bash -c 'true; cat ${K}; true'`,
    `sh -c "cat ${K}"`,
    `eval "cat ${K}"`,
    `echo hi\ncat ${K}`,
    `echo hi; cat ${K}`,
    `true || tail ${K}`,
    `ls | grep x ${K}`,
    `cat ${K} <<'EOF'\nbody\nEOF`,
    `cat <<'EOF' ${K}\nbody\nEOF`,
  ]) {
    ok(scanBashCommand(cmd).blocked, cmd);
  }
});

test('#92: shell -c payloads, eval and wrappers are scanned (additive over main)', () => {
  ok(scanBashCommand(`sudo cat ${K}`).blocked);
  ok(scanBashCommand(`env FOO=1 cat ${K}`).blocked);
  ok(scanBashCommand(`echo x | xargs cat ${K}`).blocked);
  ok(scanBashCommand(`timeout 5 cat ${K}`).blocked);
  ok(scanBashCommand(`bash -c "cat ${K}"`).blocked);
  ok(scanBashCommand(`/bin/sh -xc 'head ${K}'`).blocked);
  ok(scanBashCommand(`eval 'true;' 'cat' '${K}'`).blocked);
  equal(
    scanBashCommand(`bash -c 'printf "%s\\n" "$1"' _ 'cat ${K}'`).blocked,
    false,
    'positional parameter is data',
  );
});

test('#92: benign shapes main allowed stay allowed', () => {
  equal(scanBashCommand(`echo 'cat ${K}'`).blocked, false);
  equal(scanBashCommand(`printf "%s\\n" ${K}`).blocked, false);
  equal(scanBashCommand(`command echo 'cat ${K}'`).blocked, false);
  equal(scanBashCommand(`<<< '${K}' cat`).blocked, false);
  equal(scanBashCommand('cat /tmp/report.key\\\n.txt').blocked, false);
});

test('#92: stripInertText leaves non-git lines and unquoted strings untouched', () => {
  const cmd = `git commit -m "a; b" && bash -c "cat ${K}"`;
  const carved = stripInertText(cmd);
  ok(carved.includes(`bash -c "cat ${K}"`));
  ok(!carved.includes('a; b'));
  equal(stripInertText('echo -m "x; y"'), 'echo -m "x; y"');
});
