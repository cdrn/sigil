import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import {
  encodeError,
  encodeSuccess,
  MCP_INVALID_REQUEST,
  parseMessage,
} from '../../src/mcp/protocol.js';

// ---------------------------------------------------------------------------
// parseMessage
// ---------------------------------------------------------------------------

test('parseMessage: valid request with all fields', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":1,"method":"tools/list"}');
  ok(p.kind === 'request');
  if (p.kind !== 'request') return;
  equal(p.request.id, 1);
  equal(p.request.method, 'tools/list');
});

test('parseMessage: valid request with params', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}');
  ok(p.kind === 'request');
  if (p.kind !== 'request') return;
  deepEqual(p.request.params, { name: 'x' });
});

test('parseMessage: valid notification (no id)', () => {
  const p = parseMessage('{"jsonrpc":"2.0","method":"notifications/initialized"}');
  ok(p.kind === 'notification');
  if (p.kind !== 'notification') return;
  equal(p.notification.method, 'notifications/initialized');
});

test('parseMessage: notification with params', () => {
  const p = parseMessage('{"jsonrpc":"2.0","method":"notifications/progress","params":{"x":1}}');
  ok(p.kind === 'notification');
  if (p.kind !== 'notification') return;
  deepEqual(p.notification.params, { x: 1 });
});

test('parseMessage: id can be null', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":null,"method":"tools/list"}');
  ok(p.kind === 'request');
  if (p.kind !== 'request') return;
  equal(p.request.id, null);
});

test('parseMessage: id can be string', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":"abc","method":"x"}');
  ok(p.kind === 'request');
  if (p.kind !== 'request') return;
  equal(p.request.id, 'abc');
});

test('parseMessage: malformed JSON → parse_error', () => {
  equal(parseMessage('{not json').kind, 'parse_error');
});

test('parseMessage: non-object → invalid', () => {
  equal(parseMessage('[]').kind, 'invalid');
  equal(parseMessage('"hi"').kind, 'invalid');
});

test('parseMessage: missing jsonrpc field → invalid (preserves id)', () => {
  const p = parseMessage('{"id":3,"method":"x"}');
  ok(p.kind === 'invalid');
  if (p.kind !== 'invalid') return;
  equal(p.id, 3);
  ok(/jsonrpc/.test(p.reason));
});

test('parseMessage: wrong jsonrpc version → invalid', () => {
  const p = parseMessage('{"jsonrpc":"1.0","id":3,"method":"x"}');
  ok(p.kind === 'invalid');
});

test('parseMessage: missing method → invalid', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":1}');
  ok(p.kind === 'invalid');
  if (p.kind !== 'invalid') return;
  ok(/method/.test(p.reason));
});

test('parseMessage: empty method string → invalid', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":1,"method":""}');
  ok(p.kind === 'invalid');
});

test('parseMessage: bad id type (object) → invalid id=null', () => {
  const p = parseMessage('{"jsonrpc":"2.0","id":{"x":1},"method":"foo"}');
  ok(p.kind === 'invalid');
  if (p.kind !== 'invalid') return;
  equal(p.id, null);
});

// ---------------------------------------------------------------------------
// encodeSuccess / encodeError
// ---------------------------------------------------------------------------

test('encodeSuccess produces a JSON-RPC success envelope', () => {
  deepEqual(JSON.parse(encodeSuccess(1, { ok: true })), {
    jsonrpc: '2.0', id: 1, result: { ok: true },
  });
});

test('encodeError default omits data field', () => {
  const parsed = JSON.parse(encodeError(1, MCP_INVALID_REQUEST, 'oops')) as { error: object };
  ok(!('data' in parsed.error), 'data should be absent');
});

test('encodeError preserves data field when supplied', () => {
  const parsed = JSON.parse(encodeError(1, MCP_INVALID_REQUEST, 'oops', { x: 1 })) as {
    error: { data: { x: number } };
  };
  equal(parsed.error.data.x, 1);
});
