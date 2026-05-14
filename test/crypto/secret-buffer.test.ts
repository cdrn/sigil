import { test } from 'node:test';
import { deepEqual, doesNotThrow, equal, throws } from 'node:assert/strict';
import { inspect } from 'node:util';
import {
  SecretBuffer,
  SecretBufferDisposedError,
  SecretBufferSerializeError,
} from '../../src/crypto/secret-buffer.js';

test('bytes() returns the stored value', () => {
  const sb = new SecretBuffer(Buffer.from([1, 2, 3]));
  deepEqual(Array.from(sb.bytes()), [1, 2, 3]);
});

test('constructor copies input — mutating source does not affect SecretBuffer', () => {
  const source = Buffer.from([1, 2, 3]);
  const sb = new SecretBuffer(source);
  source.fill(0xff);
  deepEqual(Array.from(sb.bytes()), [1, 2, 3]);
});

test('dispose() actually zeroes the underlying buffer', () => {
  const sb = new SecretBuffer(Buffer.from([1, 2, 3, 4, 5]));
  const inner = sb.bytes(); // hold a ref to verify
  sb.dispose();
  deepEqual(Array.from(inner), [0, 0, 0, 0, 0]);
});

test('bytes() after dispose throws', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  sb.dispose();
  throws(() => sb.bytes(), SecretBufferDisposedError);
});

test('length after dispose throws', () => {
  const sb = new SecretBuffer(Buffer.from([1, 2, 3]));
  sb.dispose();
  throws(() => sb.length, SecretBufferDisposedError);
});

test('double dispose is safe', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  sb.dispose();
  doesNotThrow(() => sb.dispose());
});

test('isDisposed reports correct state', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  equal(sb.isDisposed, false);
  sb.dispose();
  equal(sb.isDisposed, true);
});

test('toString throws SecretBufferSerializeError', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  throws(() => sb.toString(), SecretBufferSerializeError);
});

test('toJSON throws SecretBufferSerializeError', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  throws(() => sb.toJSON(), SecretBufferSerializeError);
});

test('JSON.stringify throws (via toJSON)', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  throws(() => JSON.stringify(sb), SecretBufferSerializeError);
});

test('util.inspect does not expose the bytes', () => {
  const sb = new SecretBuffer(Buffer.from([0xde, 0xad, 0xbe, 0xef]));
  const out = inspect(sb);
  equal(out, '<SecretBuffer redacted>');
});

test('util.inspect after dispose reports disposed', () => {
  const sb = new SecretBuffer(Buffer.from([1]));
  sb.dispose();
  equal(inspect(sb), '<SecretBuffer disposed>');
});

test('length returns the byte length', () => {
  const sb = new SecretBuffer(Buffer.alloc(32, 0x42));
  equal(sb.length, 32);
});
