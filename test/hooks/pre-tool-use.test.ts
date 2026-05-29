import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { homedir } from 'node:os';
import { decidePreToolUse } from '../../src/hooks/pre-tool-use.js';

test('Read of a blocked path → block', () => {
  const d = decidePreToolUse({
    tool_name: 'Read',
    tool_input: { file_path: `${homedir()}/.sigil/keys/evm:bot.sigil` },
  });
  ok(d);
  equal(d!.decision, 'block');
  ok(/sigil ward/.test(d!.reason));
});

test('Read of a safe path → allow (null)', () => {
  const d = decidePreToolUse({
    tool_name: 'Read',
    tool_input: { file_path: '/etc/hostname' },
  });
  equal(d, null);
});

test('Read with missing file_path → allow', () => {
  const d = decidePreToolUse({
    tool_name: 'Read',
    tool_input: {},
  });
  equal(d, null);
});

test('Bash with blocked path argument → block', () => {
  const d = decidePreToolUse({
    tool_name: 'Bash',
    tool_input: { command: 'cat ~/.ssh/id_rsa' },
  });
  ok(d);
  equal(d!.decision, 'block');
});

test('Bash with innocuous command → allow', () => {
  const d = decidePreToolUse({
    tool_name: 'Bash',
    tool_input: { command: 'echo hello' },
  });
  equal(d, null);
});

test('non-warded tool → allow', () => {
  const d = decidePreToolUse({
    tool_name: 'Edit',
    tool_input: { file_path: '/anywhere' },
  });
  equal(d, null);
});

test('extraPatterns are honored on Read', () => {
  const d = decidePreToolUse(
    { tool_name: 'Read', tool_input: { file_path: '/repo/secret-cluster.yaml' } },
    { extraPatterns: ['**/secret-*.yaml'] },
  );
  ok(d);
});
