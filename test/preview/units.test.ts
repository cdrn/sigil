import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import {
  formatUnits,
  groupThousands,
  hexQuantity,
  sanitizeSymbol,
} from '../../src/preview/units.js';

test('groupThousands / formatUnits: exact, linear, and capped', () => {
  equal(groupThousands(0n), '0');
  equal(groupThousands(999n), '999');
  equal(groupThousands(1000n), '1,000');
  equal(groupThousands(-1234567n), '-1,234,567');
  equal(formatUnits(1_000_500_000n, 6), '1,000.5');
  equal(formatUnits(10n ** 18n, 18), '1');
  equal(formatUnits(1n, 18), '0.000000000000000001');
  equal(formatUnits((1n << 256n) - 1n, 0).length, 103); // uint256 max still renders
  // A 100k-hex-digit value used to take seconds in a backtracking regex.
  const huge = BigInt('0x' + 'f'.repeat(100_000));
  const start = Date.now();
  equal(groupThousands(huge), '≥1e80 (not a real amount)');
  equal(formatUnits(-huge, 18), '-≥1e80 (not a real amount)');
  ok(Date.now() - start < 200, `${Date.now() - start} ms`);
});

test('hexQuantity accepts at most uint256 width', () => {
  equal(hexQuantity('0x5208'), 21000n);
  equal(hexQuantity('0x' + 'f'.repeat(64)), (1n << 256n) - 1n);
  equal(hexQuantity('0x' + '1'.repeat(65)), null);
  equal(hexQuantity('0x'), null);
  equal(hexQuantity('5208'), null);
  equal(hexQuantity(21000), null);
});

test('sanitizeSymbol trims NUL padding without a regex and refuses long input', () => {
  equal(sanitizeSymbol('MKR\0\0\0'), 'MKR');
  equal(sanitizeSymbol('A'.repeat(100_000)), undefined);
  equal(sanitizeSymbol('US DC'), undefined);
});
