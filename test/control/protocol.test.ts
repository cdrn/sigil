import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import { isControlError, parseControlRequest } from '../../src/control/index.js';

test('parseControlRequest: lock/status methods', () => {
  deepEqual(parseControlRequest(JSON.stringify({ method: 'lock' })), { method: 'lock' });
  deepEqual(parseControlRequest(JSON.stringify({ method: 'status' })), { method: 'status' });
});

test('parseControlRequest: unlock requires passphraseB64 string', () => {
  deepEqual(parseControlRequest(JSON.stringify({ method: 'unlock', passphraseB64: 'YWJj' })), {
    method: 'unlock',
    passphraseB64: 'YWJj',
  });
  const missing = parseControlRequest(JSON.stringify({ method: 'unlock' }));
  ok('ok' in missing && missing.ok === false);
  if ('ok' in missing && missing.ok === false) equal(missing.code, 'INVALID_REQUEST');
  const nonString = parseControlRequest(JSON.stringify({ method: 'unlock', passphraseB64: 123 }));
  ok('ok' in nonString && nonString.ok === false);
});

test('parseControlRequest: unknown method', () => {
  const r = parseControlRequest(JSON.stringify({ method: 'wat' }));
  ok('ok' in r && r.ok === false);
  if ('ok' in r && r.ok === false) equal(r.code, 'UNKNOWN_METHOD');
});

test('parseControlRequest: not JSON / not object / no method', () => {
  const a = parseControlRequest('{not json');
  ok('ok' in a && a.ok === false);
  const b = parseControlRequest(JSON.stringify([1, 2]));
  ok('ok' in b && b.ok === false);
  const c = parseControlRequest(JSON.stringify(42));
  ok('ok' in c && c.ok === false);
  const d = parseControlRequest(JSON.stringify({}));
  ok('ok' in d && d.ok === false);
  if ('ok' in d && d.ok === false) equal(d.code, 'INVALID_REQUEST');
});

test('isControlError narrows the type correctly', () => {
  ok(isControlError({ ok: false, code: 'INTERNAL', error: 'x' }));
  ok(
    !isControlError({
      ok: true,
      version: 1,
      pid: 1,
      unlocked: false,
      portals: [],
    }),
  );
});
