import { test } from 'node:test';
import { equal } from 'node:assert/strict';
import { keccak256 } from '../../src/eth/keccak.js';

test('keccak256 of empty input matches the well-known value', () => {
  equal(
    keccak256(Buffer.alloc(0)).toString('hex'),
    'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  );
});

test('keccak256("abc") matches known vector', () => {
  equal(
    keccak256(Buffer.from('abc', 'ascii')).toString('hex'),
    '4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45',
  );
});

test('keccak256 produces 32-byte output', () => {
  equal(keccak256(Buffer.from('whatever')).length, 32);
});
