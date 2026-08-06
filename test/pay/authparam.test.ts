import { test } from 'node:test';
import { equal } from 'node:assert/strict';
import { parsePaymentChallenges } from '../../src/pay/index.js';

test('parses a single Payment challenge with quoted params', () => {
  const [ch] = parsePaymentChallenges([
    'Payment id="abc123", realm="api.example.com", method="tempo", intent="charge", request="eyJhIjoxfQ"',
  ]);
  equal(ch!.params['id'], 'abc123');
  equal(ch!.params['realm'], 'api.example.com');
  equal(ch!.params['method'], 'tempo');
  equal(ch!.params['intent'], 'charge');
  equal(ch!.params['request'], 'eyJhIjoxfQ');
});

test('parses multiple challenges folded into one header value', () => {
  const challenges = parsePaymentChallenges([
    'Payment id="a", realm="r", method="tempo", intent="charge", request="e30", ' +
      'Payment id="b", realm="r", method="stripe", intent="charge", request="e30"',
  ]);
  equal(challenges.length, 2);
  equal(challenges[0]!.params['id'], 'a');
  equal(challenges[1]!.params['method'], 'stripe');
});

test('skips non-Payment schemes sharing the header', () => {
  const challenges = parsePaymentChallenges([
    'Bearer realm="other", Payment id="x", realm="r", method="tempo", intent="charge", request="e30"',
  ]);
  equal(challenges.length, 1);
  equal(challenges[0]!.params['id'], 'x');
  // Bearer's realm must not leak into the Payment challenge.
  equal(challenges[0]!.params['realm'], 'r');
});

test('handles escaped quotes and unquoted token values', () => {
  const [ch] = parsePaymentChallenges(['Payment id=tok123, description="a \\"b\\" c"']);
  equal(ch!.params['id'], 'tok123');
  equal(ch!.params['description'], 'a "b" c');
});

test('param names are lowercased; unterminated quote ends that header only', () => {
  const challenges = parsePaymentChallenges([
    'Payment ID="upper", REALM="r',
    'Payment id="ok", realm="r2", method="m", intent="i", request="e30"',
  ]);
  equal(challenges.length, 2);
  equal(challenges[0]!.params['id'], 'upper');
  equal(challenges[0]!.params['realm'], undefined);
  equal(challenges[1]!.params['realm'], 'r2');
});

test('a real boutique-shaped challenge parses cleanly', () => {
  const header =
    'Payment id="J29tnBmLoQecCqFSGuIQHll2qM2riYZXLJj4dn5bnvg", ' +
    'realm="mpp-irl-demo.vercel.app", method="tempo", intent="charge", ' +
    'request="eyJhbW91bnQiOiIxMDAwMCJ9", description="Tempo Hat", ' +
    'expires="2026-08-06T21:14:46.523Z"';
  const [ch] = parsePaymentChallenges([header]);
  equal(ch!.params['expires'], '2026-08-06T21:14:46.523Z');
  equal(ch!.params['description'], 'Tempo Hat');
});
