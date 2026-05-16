import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { decidePostToolUse, walkAndRedact } from '../../src/hooks/post-tool-use.js';

test('decidePostToolUse: returns null when nothing in response needs redaction', () => {
  const r = decidePostToolUse({
    tool_name: 'Read',
    tool_response: { content: 'normal text' },
  });
  equal(r, null);
});

test('decidePostToolUse: returns null when there is no tool_response', () => {
  equal(decidePostToolUse({ tool_name: 'Read' }), null);
});

test('decidePostToolUse: emits an updatedToolResponse when a secret is found', () => {
  const key = '0x' + 'a'.repeat(64);
  const r = decidePostToolUse({
    tool_name: 'Read',
    tool_response: { content: `key=${key}` },
  });
  ok(r);
  const updated = r!.hookSpecificOutput.updatedToolResponse as { content: string };
  ok(updated.content.includes('<REDACTED:hex-private-key>'));
  equal(updated.content.includes('aaaaaaaa'), false);
});

test('decidePostToolUse: emits hookEventName PostToolUse', () => {
  const key = '0x' + 'a'.repeat(64);
  const r = decidePostToolUse({
    tool_name: 'Read',
    tool_response: `key=${key}`,
  });
  ok(r);
  equal(r!.hookSpecificOutput.hookEventName, 'PostToolUse');
});

test('walkAndRedact: recurses into nested objects and arrays', () => {
  const key = '0x' + 'b'.repeat(64);
  const input = {
    a: 1,
    b: `prefix ${key} suffix`,
    nested: { c: `${key}` },
    arr: [`${key}`, 'safe'],
  };
  const totals = new Map<string, number>();
  const out = walkAndRedact(input, totals) as typeof input;
  ok(!String(out.b).includes('bbbbb'));
  ok(!String(out.nested.c).includes('bbbbb'));
  ok(!String(out.arr[0]).includes('bbbbb'));
  equal(out.arr[1], 'safe');
  equal(out.a, 1);
  // Three hex-private-key matches across nested fields.
  equal(totals.get('hex-private-key'), 3);
});

test('walkAndRedact: leaves non-string primitives alone', () => {
  const totals = new Map<string, number>();
  deepEqual(walkAndRedact(42, totals), 42);
  deepEqual(walkAndRedact(null, totals), null);
  deepEqual(walkAndRedact(true, totals), true);
});
