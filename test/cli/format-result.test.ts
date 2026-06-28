import { test } from 'node:test';
import { equal, match, doesNotMatch } from 'node:assert/strict';
import { formatResult } from '../../src/cli/unlock.js';
import type { SessionResult } from '../../src/control/index.js';
import { CONTROL_SOCKET_VERSION } from '../../src/control/index.js';

// --- builders for SessionResult fixtures ------------------------------------

let nextPid = 1;
function base(): { pid: number; socketPath: string } {
  const pid = nextPid++;
  return { pid, socketPath: `/tmp/${pid}.sock` };
}

/** A session that unlocked (ok: true) with the given portal handles. */
function unlocked(...handles: string[]): SessionResult {
  return {
    ...base(),
    reaped: false,
    response: {
      ok: true,
      version: CONTROL_SOCKET_VERSION,
      pid: 0,
      unlocked: true,
      portals: handles.map((h) => ({ handle: h, kind: 'evm' as const, address: '0x' + h })),
    },
  };
}

/** A session that returned a server-side error with the given code. */
function errored(code: string, error = 'boom'): SessionResult {
  return {
    ...base(),
    reaped: false,
    response: { ok: false, code: code as never, error },
  };
}

/** A session that was unreachable (and possibly reaped). */
function down(reaped = true): SessionResult {
  return {
    ...base(),
    reaped,
    response: null,
    clientError: Object.assign(new Error('control socket: ENOENT'), { code: 'SERVER_DOWN' }) as never,
  };
}

// --- unlock aggregation -----------------------------------------------------

test('formatResult unlock: zero sessions → not running, exit 1', () => {
  const r = formatResult('unlock', []);
  equal(r.code, 1);
  match(r.message, /not running/i);
});

test('formatResult unlock: all sessions unreachable/reaped → not running, exit 1', () => {
  const r = formatResult('unlock', [down(), down()]);
  equal(r.code, 1);
  match(r.message, /not running/i);
});

test('formatResult unlock: two sessions unlock → "unlocked 2 sessions" with unioned portals', () => {
  const r = formatResult('unlock', [unlocked('evm:a'), unlocked('evm:a', 'evm:b')]);
  equal(r.code, 0);
  match(r.message, /unlocked 2 sessions/);
  match(r.message, /evm:a/);
  match(r.message, /evm:b/);
  // de-duped: evm:a appears once
  equal(r.message.match(/evm:a/g)?.length, 1);
});

test('formatResult unlock: fresh unlock with no keyfiles → accurate "no portals on disk"', () => {
  const r = formatResult('unlock', [unlocked()]);
  equal(r.code, 0);
  match(r.message, /unlocked 1 session/);
  match(r.message, /no portals on disk/);
});

test('formatResult unlock: already-unlocked WITH portals does NOT claim "no portals on disk"', () => {
  // Regression for the bug where ALREADY_UNLOCKED contributed no portals and
  // the message wrongly said "no portals on disk yet". A current server reports
  // already-unlocked as ok:true with its real portals, so the claim is correct.
  const r = formatResult('unlock', [unlocked('evm:main')]);
  equal(r.code, 0);
  match(r.message, /evm:main/);
  doesNotMatch(r.message, /no portals on disk/);
});

test('formatResult unlock: legacy ALREADY_UNLOCKED (no portal info) → success, no false "no portals" claim', () => {
  // Forward-compat: an older sigil-mcp still emits ALREADY_UNLOCKED with no
  // portal list. We count it as unlocked but must NOT assert "no portals on
  // disk" — we simply don't know.
  const r = formatResult('unlock', [errored('ALREADY_UNLOCKED', 'already unlocked')]);
  equal(r.code, 0);
  match(r.message, /unlocked 1 session/);
  doesNotMatch(r.message, /no portals on disk/);
});

test('formatResult unlock: wrong passphrase (even mixed with a success) → exit 2', () => {
  const r = formatResult('unlock', [unlocked('evm:a'), errored('WRONG_PASSPHRASE', 'wrong')]);
  equal(r.code, 2);
  match(r.message, /wrong passphrase/i);
});

test('formatResult unlock: one success + one KEYS_LOAD_FAILED → exit 0, notes the failure', () => {
  const r = formatResult('unlock', [unlocked('evm:a'), errored('KEYS_LOAD_FAILED', 'bad keyfile')]);
  equal(r.code, 0);
  match(r.message, /unlocked 1 session/);
  match(r.message, /1 session\(s\) failed to unlock/);
});

test('formatResult unlock: all sessions fail to load → exit 1 with the error detail', () => {
  const r = formatResult('unlock', [errored('KEYS_LOAD_FAILED', 'corrupt'), errored('INTERNAL', 'kaboom')]);
  equal(r.code, 1);
  match(r.message, /corrupt|kaboom/);
});

// --- lock aggregation -------------------------------------------------------

test('formatResult lock: counts locked sessions', () => {
  equal(formatResult('lock', [unlocked('x')]).message, 'locked 1 session');
  const two = formatResult('lock', [unlocked('x'), unlocked('y')]);
  equal(two.code, 0);
  equal(two.message, 'locked 2 sessions');
});

test('formatResult lock: nothing running → exit 1', () => {
  const r = formatResult('lock', []);
  equal(r.code, 1);
  match(r.message, /not running/i);
});
