import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import { startAckServer } from '../../src/confirm/ack-server.js';
import { ConfirmGate } from '../../src/confirm/gate.js';
import type { ConfirmRequest, ConfirmTransport } from '../../src/confirm/types.js';

/**
 * Test transport that records sends and lets the test drive the human-click
 * step by hitting the captured approveUrl / denyUrl. Tests use the REAL ack
 * server so the token-binding, timeout, and HTTP plumbing all exercise.
 */
class RecorderTransport implements ConfirmTransport {
  readonly name = 'recorder';
  readonly sends: ConfirmRequest[] = [];
  failNext: Error | undefined;
  async send(req: ConfirmRequest): Promise<void> {
    if (this.failNext) {
      const err = this.failNext;
      this.failNext = undefined;
      throw err;
    }
    this.sends.push(req);
  }
}

async function click(url: string): Promise<void> {
  await fetch(url, { method: 'POST' });
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

test('gate: approve click → decision.kind=approved', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
    const pending = gate.request({ portal: 'evm:bot', summary: '0.5 ETH → 0xabc…f0 on chain 1' });
    // Wait one tick so the transport has captured the send.
    await new Promise((r) => setImmediate(r));
    equal(transport.sends.length, 1);
    await click(transport.sends[0]!.approveUrl);
    const d = await pending;
    equal(d.kind, 'approved');
  } finally {
    await ack.close();
  }
});

test('gate: deny click → decision.kind=denied', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
    const pending = gate.request({ portal: 'evm:bot', summary: 'x' });
    await new Promise((r) => setImmediate(r));
    await click(transport.sends[0]!.denyUrl);
    const d = await pending;
    equal(d.kind, 'denied');
  } finally {
    await ack.close();
  }
});

// ---------------------------------------------------------------------------
// Transport-side failures fail closed
// ---------------------------------------------------------------------------

test('gate: transport throw → transport_error (no fallback approval)', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  transport.failNext = new Error('ECONNREFUSED');
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
    const d = await gate.request({ portal: 'evm:bot', summary: 'x' });
    equal(d.kind, 'transport_error');
    if (d.kind === 'transport_error') ok(/ECONNREFUSED/.test(d.message));
  } finally {
    await ack.close();
  }
});

test('gate: after transport failure, the token is cancelled so late clicks 410', async () => {
  // Have to capture the URL BEFORE send fails — so use a transport that
  // captures and then throws.
  class CaptureAndThrow implements ConfirmTransport {
    readonly name = 'capture+throw';
    captured?: ConfirmRequest;
    async send(req: ConfirmRequest): Promise<void> {
      this.captured = req;
      throw new Error('boom');
    }
  }
  const ack = await startAckServer();
  const transport = new CaptureAndThrow();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
    const d = await gate.request({ portal: 'evm:bot', summary: 'x' });
    equal(d.kind, 'transport_error');
    // A late click for the cancelled token returns 410.
    const r = await fetch(transport.captured!.approveUrl, { method: 'POST' });
    equal(r.status, 410);
  } finally {
    await ack.close();
  }
});

// ---------------------------------------------------------------------------
// Timeout
// ---------------------------------------------------------------------------

test('gate: no click within timeoutMs → timeout', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 30 });
    const t0 = Date.now();
    const d = await gate.request({ portal: 'evm:bot', summary: 'x' });
    const elapsed = Date.now() - t0;
    equal(d.kind, 'timeout');
    ok(elapsed >= 25, `elapsed ${elapsed}ms < 25ms — timer fired suspiciously early`);
  } finally {
    await ack.close();
  }
});

test('gate: after timeout, late click returns 410 (not a stale approval)', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 30 });
    const d = await gate.request({ portal: 'evm:bot', summary: 'x' });
    equal(d.kind, 'timeout');
    const url = transport.sends[0]!.approveUrl;
    const r = await fetch(url, { method: 'POST' });
    equal(r.status, 410);
  } finally {
    await ack.close();
  }
});

// ---------------------------------------------------------------------------
// Concurrent requests don't cross-resolve
// ---------------------------------------------------------------------------

test('gate: concurrent confirms are token-isolated', async () => {
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
    const pA = gate.request({ portal: 'evm:a', summary: 'A' });
    const pB = gate.request({ portal: 'evm:b', summary: 'B' });
    await new Promise((r) => setImmediate(r));
    equal(transport.sends.length, 2);
    const reqA = transport.sends.find((s) => s.portal === 'evm:a')!;
    const reqB = transport.sends.find((s) => s.portal === 'evm:b')!;
    ok(reqA.token !== reqB.token, 'tokens must differ');
    // Approve only A.
    await click(reqA.approveUrl);
    equal((await pA).kind, 'approved');
    // B is still pending — confirm by hitting it after.
    await click(reqB.denyUrl);
    equal((await pB).kind, 'denied');
  } finally {
    await ack.close();
  }
});

// ---------------------------------------------------------------------------
// Token-binding: a token from request A cannot approve request B
// ---------------------------------------------------------------------------

test('gate: a token issued to request A only resolves request A (deny-by-construction)', async () => {
  // This is really an ack-server property (already tested there), but
  // verifying through the gate guards the seam.
  const ack = await startAckServer();
  const transport = new RecorderTransport();
  try {
    const gate = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 100 });
    const pA = gate.request({ portal: 'evm:a', summary: 'A' });
    const pB = gate.request({ portal: 'evm:b', summary: 'B' });
    await new Promise((r) => setImmediate(r));
    const reqA = transport.sends.find((s) => s.portal === 'evm:a')!;
    // Approve A. B should still time out — not implicitly approved.
    await click(reqA.approveUrl);
    equal((await pA).kind, 'approved');
    equal((await pB).kind, 'timeout');
  } finally {
    await ack.close();
  }
});

// ---------------------------------------------------------------------------
// Public surface checks
// ---------------------------------------------------------------------------

test('gate: transportName surfaces the underlying transport name', async () => {
  const ack = await startAckServer();
  try {
    const gate = new ConfirmGate({
      transport: new RecorderTransport(),
      ackServer: ack,
      timeoutMs: 10,
    });
    equal(gate.transportName, 'recorder');
  } finally {
    await ack.close();
  }
});
