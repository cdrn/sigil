import { test } from 'node:test';
import { deepEqual, equal, ok, rejects, throws } from 'node:assert/strict';
import { NtfyTransport, type FetchLike } from '../../src/confirm/ntfy.js';
import type { ConfirmRequest } from '../../src/confirm/types.js';

function req(over: Partial<ConfirmRequest> = {}): ConfirmRequest {
  return {
    portal: 'evm:bot',
    summary: '0.5 ETH → 0x1234…dead on chain 1',
    approveUrl: 'http://127.0.0.1:42424/approve?t=abc',
    denyUrl: 'http://127.0.0.1:42424/deny?t=abc',
    token: 'abc',
    ...over,
  };
}

interface CapturedCall {
  url: string;
  headers: Record<string, string>;
  body?: string;
}

function captureFetch(
  status: number = 200,
  statusText: string = 'OK',
): { fetch: FetchLike; calls: CapturedCall[] } {
  const calls: CapturedCall[] = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, headers: init.headers, ...(init.body !== undefined ? { body: init.body } : {}) });
    return { ok: status >= 200 && status < 300, status, statusText };
  };
  return { fetch, calls };
}

// ---------------------------------------------------------------------------
// URL construction
// ---------------------------------------------------------------------------

test('ntfy: posts to <server>/<topic> with default server', async () => {
  const { fetch, calls } = captureFetch();
  const t = new NtfyTransport({ topic: 'my-secret-topic' }, fetch);
  await t.send(req());
  equal(calls.length, 1);
  equal(calls[0]!.url, 'https://ntfy.sh/my-secret-topic');
});

test('ntfy: honours custom self-hosted server', async () => {
  const { fetch, calls } = captureFetch();
  const t = new NtfyTransport({ topic: 'sec', server: 'https://ntfy.example.com' }, fetch);
  await t.send(req());
  equal(calls[0]!.url, 'https://ntfy.example.com/sec');
});

test('ntfy: trims trailing slashes from server URL', async () => {
  const { fetch, calls } = captureFetch();
  const t = new NtfyTransport({ topic: 'sec', server: 'https://ntfy.example.com///' }, fetch);
  await t.send(req());
  equal(calls[0]!.url, 'https://ntfy.example.com/sec');
});

test('ntfy: rejects topic that looks like a pasted URL', () => {
  throws(
    () => new NtfyTransport({ topic: 'https://ntfy.sh/topic' }),
    /must match \[A-Za-z0-9_-\]\+/,
  );
});

test('ntfy: rejects empty topic', () => {
  throws(() => new NtfyTransport({ topic: '' }), /must match/);
});

// ---------------------------------------------------------------------------
// Headers + body
// ---------------------------------------------------------------------------

test('ntfy: sets Title to portal handle (sigil-prefixed)', async () => {
  const { fetch, calls } = captureFetch();
  await new NtfyTransport({ topic: 't' }, fetch).send(req({ portal: 'evm:executor' }));
  equal(calls[0]!.headers['Title'], 'sigil — evm:executor');
});

test('ntfy: sets Priority: high so the push bypasses quiet hours', async () => {
  const { fetch, calls } = captureFetch();
  await new NtfyTransport({ topic: 't' }, fetch).send(req());
  equal(calls[0]!.headers['Priority'], 'high');
});

test('ntfy: Click header points at the approve URL (one-tap approve from body)', async () => {
  const { fetch, calls } = captureFetch();
  const r = req({ approveUrl: 'http://127.0.0.1:9/a?t=xx' });
  await new NtfyTransport({ topic: 't' }, fetch).send(r);
  equal(calls[0]!.headers['Click'], 'http://127.0.0.1:9/a?t=xx');
});

test('ntfy: Actions header carries both Approve and Deny POST buttons', async () => {
  const { fetch, calls } = captureFetch();
  const r = req({
    approveUrl: 'http://127.0.0.1:9/a?t=xx',
    denyUrl: 'http://127.0.0.1:9/d?t=xx',
  });
  await new NtfyTransport({ topic: 't' }, fetch).send(r);
  const actions = calls[0]!.headers['Actions']!;
  ok(/http, Approve, http:\/\/127\.0\.0\.1:9\/a\?t=xx, method=POST/.test(actions), actions);
  ok(/http, Deny, http:\/\/127\.0\.0\.1:9\/d\?t=xx, method=POST/.test(actions), actions);
});

test('ntfy: body carries the human-readable summary', async () => {
  const { fetch, calls } = captureFetch();
  await new NtfyTransport({ topic: 't' }, fetch).send(req({ summary: '1.5 ETH → 0xabc…f0 on chain 8453' }));
  equal(calls[0]!.body, '1.5 ETH → 0xabc…f0 on chain 8453');
});

// ---------------------------------------------------------------------------
// Failure modes
// ---------------------------------------------------------------------------

test('ntfy: non-2xx response throws so the gate can fail closed', async () => {
  const { fetch } = captureFetch(503, 'Service Unavailable');
  const t = new NtfyTransport({ topic: 't' }, fetch);
  await rejects(() => t.send(req()), /HTTP 503 Service Unavailable/);
});

test('ntfy: fetch throw (network down) propagates to the gate', async () => {
  const fetch: FetchLike = async () => { throw new Error('ECONNREFUSED'); };
  const t = new NtfyTransport({ topic: 't' }, fetch);
  await rejects(() => t.send(req()), /ECONNREFUSED/);
});

// ---------------------------------------------------------------------------
// Interface conformance — confirms each transport has a usable name field
// ---------------------------------------------------------------------------

test('ntfy: transport name is the literal "ntfy"', () => {
  const t = new NtfyTransport({ topic: 't' }, captureFetch().fetch);
  equal(t.name, 'ntfy');
});

// Guard against header drift: keep an ordered snapshot of the header set we
// emit. If we add or remove one, this test fails so the corresponding ntfy
// docs link / comment can be updated.
test('ntfy: snapshot the exact header set we emit', async () => {
  const { fetch, calls } = captureFetch();
  await new NtfyTransport({ topic: 't' }, fetch).send(req());
  deepEqual(
    Object.keys(calls[0]!.headers).sort(),
    ['Actions', 'Click', 'Content-Type', 'Priority', 'Title'],
  );
});
