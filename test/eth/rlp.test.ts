import { test } from 'node:test';
import { deepEqual, equal } from 'node:assert/strict';
import { encodeInt, rlpDecode, rlpEncode } from '../../src/eth/rlp.js';

// Helpers
const hex = (s: string) => Buffer.from(s, 'hex');
const enc = (input: Parameters<typeof rlpEncode>[0]) => rlpEncode(input).toString('hex');

test('empty byte string encodes to 0x80', () => {
  equal(enc(Buffer.alloc(0)), '80');
});

test('single byte < 0x80 encodes as itself', () => {
  equal(enc(hex('00')), '00');
  equal(enc(hex('7f')), '7f');
});

test('single byte >= 0x80 encodes with length prefix', () => {
  equal(enc(hex('80')), '8180');
  equal(enc(hex('ff')), '81ff');
});

test('"dog" encodes to 0x83646f67 (canonical example)', () => {
  equal(enc(Buffer.from('dog', 'ascii')), '83646f67');
});

test('empty list encodes to 0xc0', () => {
  equal(enc([]), 'c0');
});

test('["cat","dog"] encodes to 0xc88363617483646f67 (canonical example)', () => {
  equal(enc([Buffer.from('cat'), Buffer.from('dog')]), 'c88363617483646f67');
});

test('long string (56 bytes) uses long-string length encoding', () => {
  const s = Buffer.alloc(56, 0x61);
  const encoded = rlpEncode(s);
  // 56 bytes → 0xb8 (length-of-length=1) + 0x38 (56) + payload
  equal(encoded[0], 0xb8);
  equal(encoded[1], 56);
  equal(encoded.length, 1 + 1 + 56);
});

test('nested list encodes correctly', () => {
  // [ [], [[]], [[], [[]]] ] — canonical "set theoretic representation of three"
  const encoded = enc([[], [[]], [[], [[]]]]);
  equal(encoded, 'c7c0c1c0c3c0c1c0');
});

test('encodeInt(0) is empty', () => {
  equal(encodeInt(0).length, 0);
});

test('encodeInt produces minimal big-endian (no leading zeros)', () => {
  equal(encodeInt(1).toString('hex'), '01');
  equal(encodeInt(15).toString('hex'), '0f');
  equal(encodeInt(255).toString('hex'), 'ff');
  equal(encodeInt(256).toString('hex'), '0100');
  equal(encodeInt(1024).toString('hex'), '0400');
  equal(encodeInt(0x10000n).toString('hex'), '010000');
});

test('encodeInt handles bigint', () => {
  equal(encodeInt(2n ** 64n).toString('hex'), '010000000000000000');
});

test('decode round-trips simple values', () => {
  const inputs: Parameters<typeof rlpEncode>[0][] = [
    Buffer.from('hello'),
    Buffer.alloc(0),
    [Buffer.from('a'), Buffer.from('b'), Buffer.from('c')],
    [],
    [[], [Buffer.from('x')]],
  ];
  for (const input of inputs) {
    const encoded = rlpEncode(input);
    const decoded = rlpDecode(encoded);
    deepEqual(JSON.stringify(decoded), JSON.stringify(input));
  }
});
