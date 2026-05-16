import { test } from 'node:test';
import { deepEqual, equal, ok } from 'node:assert/strict';
import {
  encodeError,
  encodeResponse,
  parseRequest,
  RPC_INVALID_PARAMS,
  RPC_VERSION,
} from '../../src/daemon/rpc.js';

// ---------------------------------------------------------------------------
// parseRequest
// ---------------------------------------------------------------------------

test('parseRequest: valid request with all fields', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":1,"method":"foo","params":{"x":1}}');
  ok(r.kind === 'request');
  if (r.kind !== 'request') return;
  equal(r.request.id, 1);
  equal(r.request.method, 'foo');
  deepEqual(r.request.params, { x: 1 });
});

test('parseRequest: id can be string', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":"abc","method":"foo"}');
  ok(r.kind === 'request');
  if (r.kind !== 'request') return;
  equal(r.request.id, 'abc');
});

test('parseRequest: id can be null', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":null,"method":"foo"}');
  ok(r.kind === 'request');
  if (r.kind !== 'request') return;
  equal(r.request.id, null);
});

test('parseRequest: missing params is OK (params is undefined)', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":1,"method":"foo"}');
  ok(r.kind === 'request');
});

test('parseRequest: malformed JSON returns parse_error', () => {
  const r = parseRequest('{not json');
  equal(r.kind, 'parse_error');
});

test('parseRequest: non-object (array) is invalid request with id=null', () => {
  const r = parseRequest('[]');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  equal(r.id, null);
  ok(/object/.test(r.reason));
});

test('parseRequest: non-object (string) is invalid request', () => {
  const r = parseRequest('"hi"');
  equal(r.kind, 'invalid');
});

test('parseRequest: missing jsonrpc field is invalid', () => {
  const r = parseRequest('{"id":1,"method":"foo"}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  equal(r.id, 1); // id is preserved
  ok(/jsonrpc/.test(r.reason));
});

test('parseRequest: wrong jsonrpc version is invalid', () => {
  const r = parseRequest('{"jsonrpc":"1.0","id":1,"method":"foo"}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  ok(/jsonrpc/.test(r.reason));
});

test('parseRequest: missing method is invalid', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":1}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  ok(/method/.test(r.reason));
});

test('parseRequest: empty method string is invalid', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":1,"method":""}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  ok(/method/.test(r.reason));
});

test('parseRequest: notification (missing id) is rejected', () => {
  const r = parseRequest('{"jsonrpc":"2.0","method":"foo"}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  ok(/notifications/.test(r.reason));
});

test('parseRequest: id of wrong type (boolean) is invalid', () => {
  const r = parseRequest('{"jsonrpc":"2.0","id":true,"method":"foo"}');
  ok(r.kind === 'invalid');
  if (r.kind !== 'invalid') return;
  // id can't be extracted — it's the wrong type — so falls back to null
  equal(r.id, null);
});

// ---------------------------------------------------------------------------
// encodeResponse / encodeError
// ---------------------------------------------------------------------------

test('encodeResponse produces a valid JSON-RPC response envelope', () => {
  const json = encodeResponse(1, { ok: true });
  const parsed = JSON.parse(json);
  deepEqual(parsed, { jsonrpc: RPC_VERSION, id: 1, result: { ok: true } });
});

test('encodeResponse with null id', () => {
  const json = encodeResponse(null, 42);
  deepEqual(JSON.parse(json), { jsonrpc: RPC_VERSION, id: null, result: 42 });
});

test('encodeResponse with string id', () => {
  const json = encodeResponse('abc', 'pong');
  deepEqual(JSON.parse(json), { jsonrpc: RPC_VERSION, id: 'abc', result: 'pong' });
});

test('encodeError with code + message only', () => {
  const json = encodeError(1, RPC_INVALID_PARAMS, 'bad');
  deepEqual(JSON.parse(json), {
    jsonrpc: RPC_VERSION,
    id: 1,
    error: { code: RPC_INVALID_PARAMS, message: 'bad' },
  });
});

test('encodeError with data field', () => {
  const json = encodeError(1, RPC_INVALID_PARAMS, 'bad', { detail: 'x' });
  deepEqual(JSON.parse(json), {
    jsonrpc: RPC_VERSION,
    id: 1,
    error: { code: RPC_INVALID_PARAMS, message: 'bad', data: { detail: 'x' } },
  });
});

test('encodeError omits data when undefined (not stringified as null)', () => {
  const json = encodeError(1, -32000, 'oops');
  ok(!('data' in (JSON.parse(json) as { error: object }).error), 'data should be absent');
});
