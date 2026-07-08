import { test } from 'node:test';
import { equal, ok, throws } from 'node:assert/strict';
import { encode } from '../../src/qr/index.js';

// QR module side length for version V (ISO/IEC 18004): 4V + 17.
function versionSize(version: number): number {
  return 4 * version + 17;
}

function isFinderAt(m: boolean[][], r: number, c: number): boolean {
  for (let dr = 0; dr < 7; dr++) {
    for (let dc = 0; dc < 7; dc++) {
      const onOuter = dr === 0 || dr === 6 || dc === 0 || dc === 6;
      const inCenter = dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4;
      const expect = onOuter || inCenter;
      if (m[r + dr]![c + dc] !== expect) return false;
    }
  }
  return true;
}

test('byte mode: short input yields a small square matrix', () => {
  const m = encode('hi');
  ok(m.length >= 21);
  equal(m.length, m[0]!.length);
});

test('byte mode: 42-char lowercase ETH address fits V3 (29×29)', () => {
  // V3-M byte capacity is exactly 42 bytes — the address fits with the
  // stronger default error correction at no size cost vs V3-L.
  const addr = '0xf4e9ec89224d6ed085995af612feba4418ebf88a';
  const m = encode(addr);
  equal(m.length, versionSize(3));
  equal(m.length, 29);
});

test('default error correction is M; explicit L yields a different matrix', () => {
  // Same input, same version, different EC level → different codewords.
  // Guards against the default silently regressing to L (~7% tolerance),
  // which is marginal for phone-scanning a QR off terminal glass.
  const addr = '0xf4e9ec89224d6ed085995af612feba4418ebf88a';
  const def = encode(addr);
  const atL = encode(addr, { ecLevel: 'L' });
  const atM = encode(addr, { ecLevel: 'M' });
  equal(def.length, atM.length);
  let defEqualsM = true;
  let defEqualsL = true;
  for (let r = 0; r < def.length; r++) {
    for (let c = 0; c < def.length; c++) {
      if (def[r]![c] !== atM[r]![c]) defEqualsM = false;
      if (atL.length === def.length && def[r]![c] !== atL[r]![c]) defEqualsL = false;
    }
  }
  ok(defEqualsM, 'default should be M');
  ok(!defEqualsL || atL.length !== def.length, 'L should differ from the default');
});

test('finder patterns appear at the three corners', () => {
  const m = encode('hello world');
  const size = m.length;
  ok(isFinderAt(m, 0, 0), 'top-left finder');
  ok(isFinderAt(m, 0, size - 7), 'top-right finder');
  ok(isFinderAt(m, size - 7, 0), 'bottom-left finder');
});

test('timing patterns alternate dark/light along row 6 and col 6', () => {
  const m = encode('hello world');
  const size = m.length;
  for (let i = 8; i < size - 8; i++) {
    equal(m[6]![i], i % 2 === 0, `row 6 col ${i}`);
    equal(m[i]![6], i % 2 === 0, `col 6 row ${i}`);
  }
});

test('byte mode preserves case (different from alphanumeric which uppercases)', () => {
  const lower = encode('0xabcdef');
  const upper = encode('0XABCDEF');
  // Different inputs → different matrices. (If byte mode were uppercasing,
  // these two would produce the same matrix.)
  let differ = false;
  for (let r = 0; r < lower.length && !differ; r++) {
    for (let c = 0; c < lower[0]!.length; c++) {
      if (lower[r]![c] !== upper[r]![c]) { differ = true; break; }
    }
  }
  ok(differ, 'byte-mode encoding should be case-sensitive');
});

test('alphanumeric mode rejects characters outside the alphanumeric set', () => {
  // The library would silently fall back to byte mode; our adapter
  // throws so the caller's intent is honoured.
  throws(() => encode('hello', { mode: 'Alphanumeric' }), /alphanumeric set/);
  throws(() => encode('0x' + 'a'.repeat(40), { mode: 'Alphanumeric' }), /alphanumeric set/);
});

test('alphanumeric mode accepts uppercase + digit input', () => {
  const m = encode('HELLO WORLD', { mode: 'Alphanumeric' });
  // V1-L can hold "HELLO WORLD" (11 alphanumeric chars).
  equal(m.length, versionSize(1));
});

test('rejects forced-version that cannot fit the input', () => {
  // V1-L holds 17 bytes; 50 bytes cannot possibly fit.
  throws(() => encode('A'.repeat(50), { version: 1 }));
});

test('different inputs produce different matrices (sanity vs all-identical bug)', () => {
  const a = encode('aaaaaaaa');
  const b = encode('bbbbbbbb');
  let differ = false;
  for (let r = 0; r < a.length && !differ; r++) {
    for (let c = 0; c < a.length; c++) {
      if (a[r]![c] !== b[r]![c]) { differ = true; break; }
    }
  }
  ok(differ);
});
