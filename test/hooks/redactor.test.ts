import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { redact } from '../../src/hooks/redactor.js';

test('redacts a raw 0x-prefixed 32-byte private key', () => {
  const text = 'PRIV=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef and more';
  const r = redact(text);
  ok(r.text.includes('<REDACTED:hex-private-key>'));
  equal(r.text.includes('0xdeadbeef'), false);
  equal(r.redactions[0]!.reason, 'hex-private-key');
});

test('does not redact a 32-byte hash (shorter than 64 hex chars)', () => {
  const text = 'block 0xabc123 ok';
  const r = redact(text);
  equal(r.text, text);
});

test('does not redact a 0x string longer than 64 chars (e.g. concatenated calldata)', () => {
  // 70 hex chars after 0x — too long for a private key (64). Should NOT be flagged
  // since we anchor to exactly 64.
  const longHex = '0x' + 'a'.repeat(70);
  const r = redact(`payload ${longHex}`);
  equal(r.text.includes('<REDACTED:'), false);
});

test('redacts a PEM private key block', () => {
  const text = [
    '-----BEGIN RSA PRIVATE KEY-----',
    'MIIEowIBAAKCAQEA1234',
    '-----END RSA PRIVATE KEY-----',
  ].join('\n');
  const r = redact(text);
  ok(r.text.includes('<REDACTED:pem-private-key>'));
  equal(r.text.includes('MIIEowIBAA'), false);
});

test('redacts a generic PEM KEY block (without explicit PRIVATE)', () => {
  const text = [
    '-----BEGIN EC KEY-----',
    'BASE64BLOB',
    '-----END EC KEY-----',
  ].join('\n');
  const r = redact(text);
  ok(r.text.includes('<REDACTED:pem-key-block>') || r.text.includes('<REDACTED:pem-private-key>'));
});

test('redacts a JWT-shaped token', () => {
  const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const r = redact(`Authorization: Bearer ${jwt}`);
  ok(r.text.includes('<REDACTED:jwt>'));
  equal(r.text.includes('eyJhbGciOi'), false);
});

test('redacts an npm token', () => {
  const tok = 'npm_' + 'a'.repeat(36);
  const r = redact(`token=${tok}`);
  ok(r.text.includes('<REDACTED:npm-token>'));
});

test('redacts an Anthropic API key', () => {
  const r = redact('sk-ant-api03-abc123def456ghi789');
  ok(r.text.includes('<REDACTED:anthropic-api-key>'));
});

test('redacts an AWS access key id', () => {
  const r = redact('AKIAIOSFODNN7EXAMPLE');
  ok(r.text.includes('<REDACTED:aws-access-key-id>'));
});

test('redacts multiple occurrences in one pass', () => {
  const key = '0x' + 'a'.repeat(64);
  const r = redact(`first=${key} second=${key}`);
  equal(r.text.match(/<REDACTED:hex-private-key>/g)?.length, 2);
  equal(r.redactions.find((s) => s.reason === 'hex-private-key')?.count, 2);
});

test('leaves text untouched when nothing matches', () => {
  const text = 'normal log output with no secrets';
  const r = redact(text);
  equal(r.text, text);
  equal(r.redactions.length, 0);
});
