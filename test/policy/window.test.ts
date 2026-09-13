import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import {
  checkWindowCaps,
  DAY_MS,
  HOUR_MS,
  parsePolicy,
  windowCapsFor,
} from '../../src/policy/index.js';

test('windowCapsFor: no caps when the policy sets none, for either asset', () => {
  const p = parsePolicy('mode = "permissive"\n');
  deepEqual(windowCapsFor(p, 'wei'), []);
  deepEqual(windowCapsFor(p, 'lamports'), []);
});

test('windowCapsFor: returns hourly then daily for wei, labelled by TOML field', () => {
  const p = parsePolicy(
    'mode = "permissive"\nmax_value_per_hour_wei = "10"\nmax_value_per_day_wei = "50"\n',
  );
  deepEqual(windowCapsFor(p, 'wei'), [
    { label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: 10n },
    { label: 'max_value_per_day_wei', windowMs: DAY_MS, cap: 50n },
  ]);
  deepEqual(windowCapsFor(p, 'lamports'), []);
});

test('windowCapsFor: lamports caps are independent of wei caps', () => {
  const p = parsePolicy(
    'mode = "permissive"\nsvm_max_lamports_per_day = "7"\nmax_value_per_hour_wei = "1"\n',
  );
  deepEqual(windowCapsFor(p, 'lamports'), [
    { label: 'svm_max_lamports_per_day', windowMs: DAY_MS, cap: 7n },
  ]);
  equal(windowCapsFor(p, 'wei').length, 1);
});

test('windowCapsFor: strict mode carries the same caps', () => {
  const p = parsePolicy('mode = "strict"\nchain_ids = [1]\nmax_value_per_day_wei = "5"\n');
  equal(windowCapsFor(p, 'wei')[0]!.cap, 5n);
});

const H = { label: 'max_value_per_hour_wei', windowMs: HOUR_MS, cap: 100n };
const D = { label: 'max_value_per_day_wei', windowMs: DAY_MS, cap: 1000n };

test('checkWindowCaps: zero amount never breaches, even at a zero cap', () => {
  equal(
    checkWindowCaps([{ ...H, cap: 0n }], 0n, () => 0n, 'wei'),
    null,
  );
});

test('checkWindowCaps: exactly reaching the cap is allowed; one more is denied', () => {
  equal(
    checkWindowCaps([H], 100n, () => 0n, 'wei'),
    null,
  );
  equal(
    checkWindowCaps([H], 40n, () => 60n, 'wei'),
    null,
  );
  const r = checkWindowCaps([H], 41n, () => 60n, 'wei');
  ok(r !== null && /max_value_per_hour_wei = 100/.test(r));
  ok(r !== null && /trailing 1h total to 101 wei/.test(r));
});

test('checkWindowCaps: each window is checked against its own trailing total', () => {
  const spent = (w: number) => (w === HOUR_MS ? 10n : 995n);
  equal(checkWindowCaps([H, D], 5n, spent, 'wei'), null);
  const r = checkWindowCaps([H, D], 6n, spent, 'wei');
  ok(r !== null && /24h/.test(r) && /max_value_per_day_wei/.test(r), r ?? '');
});

test('checkWindowCaps: the first breached cap in order is reported', () => {
  const r = checkWindowCaps([H, D], 200n, () => 0n, 'wei');
  ok(r !== null && /max_value_per_hour_wei/.test(r));
});

test('checkWindowCaps: unit appears in the reason', () => {
  const r = checkWindowCaps(
    [{ label: 'svm_max_lamports_per_hour', windowMs: HOUR_MS, cap: 1n }],
    2n,
    () => 0n,
    'lamports',
  );
  ok(r !== null && /2 lamports/.test(r));
});

test('checkWindowCaps: no caps → always allowed', () => {
  equal(
    checkWindowCaps([], 10n ** 30n, () => 0n, 'wei'),
    null,
  );
});
