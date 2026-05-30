import { test } from 'node:test';
import { equal, match, ok } from 'node:assert/strict';
import { startAckServer, type AckServer } from '../../src/confirm/ack-server.js';

async function withServer<T>(fn: (s: AckServer) => Promise<T>): Promise<T> {
  const s = await startAckServer();
  try {
    return await fn(s);
  } finally {
    await s.close();
  }
}

async function http(
  url: string,
  method: 'GET' | 'POST' = 'POST',
): Promise<{ status: number; body: string }> {
  const r = await fetch(url, { method });
  return { status: r.status, body: await r.text() };
}

// ---------------------------------------------------------------------------
// Bind + URL shape
// ---------------------------------------------------------------------------

test('ack server: binds 127.0.0.1 with a non-zero port', async () => {
  await withServer(async (s) => {
    match(s.baseUrl, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
  });
});

test('ack server: pending() returns approve/deny URLs that hit this server', async () => {
  await withServer(async (s) => {
    const { token, approveUrl, denyUrl } = s.pending();
    ok(approveUrl.startsWith(s.baseUrl + '/approve?t='));
    ok(denyUrl.startsWith(s.baseUrl + '/deny?t='));
    ok(approveUrl.endsWith(token));
    ok(denyUrl.endsWith(token));
  });
});

test('ack server: minted tokens are unguessable (base64url, 43 chars for 32 bytes)', async () => {
  await withServer(async (s) => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) {
      const { token } = s.pending();
      ok(/^[A-Za-z0-9_-]{43}$/.test(token), `bad token shape: ${token}`);
      ok(!seen.has(token), `token collision after ${i} iterations`);
      seen.add(token);
      s.cancel(token);
    }
  });
});

// ---------------------------------------------------------------------------
// Approve / Deny round-trip
// ---------------------------------------------------------------------------

test('ack server: POST /approve resolves the pending settled promise as "approve"', async () => {
  await withServer(async (s) => {
    const { approveUrl, settled } = s.pending();
    const resp = await http(approveUrl);
    equal(resp.status, 200);
    match(resp.body, /approved/);
    equal(await settled, 'approve');
  });
});

test('ack server: POST /deny resolves the pending settled promise as "deny"', async () => {
  await withServer(async (s) => {
    const { denyUrl, settled } = s.pending();
    const resp = await http(denyUrl);
    equal(resp.status, 200);
    match(resp.body, /denied/);
    equal(await settled, 'deny');
  });
});

test('ack server: GET works too (fallback for clients that won\'t POST from a tap)', async () => {
  await withServer(async (s) => {
    const { approveUrl, settled } = s.pending();
    const resp = await http(approveUrl, 'GET');
    equal(resp.status, 200);
    equal(await settled, 'approve');
  });
});

// ---------------------------------------------------------------------------
// Single-use + cross-request isolation
// ---------------------------------------------------------------------------

test('ack server: token is single-use — replay returns 410 Gone', async () => {
  await withServer(async (s) => {
    const { approveUrl, settled } = s.pending();
    const first = await http(approveUrl);
    equal(first.status, 200);
    await settled; // drain
    const second = await http(approveUrl);
    equal(second.status, 410);
    match(second.body, /expired or already used/);
  });
});

test('ack server: a token issued for request A cannot resolve request B', async () => {
  await withServer(async (s) => {
    const a = s.pending();
    const b = s.pending();
    // Use A's approve URL — only A should resolve.
    await http(a.approveUrl);
    equal(await a.settled, 'approve');
    // B is still pending; no resolution yet. (Verified by racing against a
    // tick — if B had also resolved, this resolves to 'b'; we expect timeout.)
    const winner = await Promise.race([
      b.settled.then((v) => `b:${v}`),
      new Promise<string>((res) => setTimeout(() => res('tick'), 50)),
    ]);
    equal(winner, 'tick');
    s.cancel(b.token);
  });
});

test('ack server: deny click on an approve-issued token is fine (same token covers both)', async () => {
  // Both endpoints share one token per pending request — the human chooses
  // approve OR deny. This test guards against an accidental refactor that
  // would issue separate tokens per direction.
  await withServer(async (s) => {
    const { denyUrl, settled } = s.pending();
    await http(denyUrl);
    equal(await settled, 'deny');
  });
});

// ---------------------------------------------------------------------------
// Cancellation (caller timeout)
// ---------------------------------------------------------------------------

test('ack server: cancel() turns subsequent clicks into 410', async () => {
  await withServer(async (s) => {
    const { token, approveUrl } = s.pending();
    s.cancel(token);
    const resp = await http(approveUrl);
    equal(resp.status, 410);
  });
});

test('ack server: cancel() does not resolve settled (gate owns the race)', async () => {
  await withServer(async (s) => {
    const { token, settled } = s.pending();
    s.cancel(token);
    // If cancel resolved settled, this race finishes with "settled".
    const winner = await Promise.race([
      settled.then(() => 'settled'),
      new Promise<string>((res) => setTimeout(() => res('tick'), 50)),
    ]);
    equal(winner, 'tick');
  });
});

test('ack server: cancel() on an unknown token is a no-op', async () => {
  await withServer(async (s) => {
    s.cancel('does-not-exist');
    // Server still serves new requests.
    const { approveUrl, settled } = s.pending();
    await http(approveUrl);
    equal(await settled, 'approve');
  });
});

// ---------------------------------------------------------------------------
// Bad inputs
// ---------------------------------------------------------------------------

test('ack server: unknown path → 404', async () => {
  await withServer(async (s) => {
    const r = await http(`${s.baseUrl}/whatever`);
    equal(r.status, 404);
  });
});

test('ack server: approve without ?t= → 400', async () => {
  await withServer(async (s) => {
    const r = await http(`${s.baseUrl}/approve`);
    equal(r.status, 400);
    match(r.body, /missing token/);
  });
});

test('ack server: approve with unknown token → 410', async () => {
  await withServer(async (s) => {
    const r = await http(`${s.baseUrl}/approve?t=bogus`);
    equal(r.status, 410);
  });
});

// ---------------------------------------------------------------------------
// Multiple servers can co-exist (port is OS-chosen)
// ---------------------------------------------------------------------------

test('ack server: two servers get distinct ports', async () => {
  const a = await startAckServer();
  const b = await startAckServer();
  try {
    ok(a.baseUrl !== b.baseUrl, `same baseUrl: ${a.baseUrl}`);
  } finally {
    await a.close();
    await b.close();
  }
});
