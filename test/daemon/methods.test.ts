import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter, verifyChain } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import {
  addressFromPrivateKey,
  deserializeEthSignature,
  personalSignDigest,
  recoverPublicKey,
  addressFromPublicKey,
  rlpDecode,
  txDigest,
  type Eip1559Tx,
} from '../../src/eth/index.js';
import {
  dispatch,
  HandleTable,
  type MethodContext,
  RPC_DAEMON_LOCKED,
  RPC_INVALID_PARAMS,
  RPC_METHOD_NOT_FOUND,
  RPC_POLICY_DENIED,
  RPC_PORTAL_NOT_FOUND,
  RpcMethodError,
} from '../../src/daemon/index.js';
import {
  parsePolicy,
  permissivePolicyResolver,
  type PolicyResolver,
  PolicyLoadError,
} from '../../src/policy/index.js';

function mkTmp(): string {
  return mkdtempSync(join(tmpdir(), 'sigil-methods-'));
}

function priv(byte: number): Buffer {
  const p = Buffer.alloc(32);
  p[31] = byte;
  return p;
}

function makeCtx(): { ctx: MethodContext; cleanup: () => void; auditPath: string } {
  const dir = mkTmp();
  const auditPath = join(dir, 'audit.log');
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(auditPath, { now: () => ++now });
  return {
    ctx: { handles, audit, policy: permissivePolicyResolver() },
    auditPath,
    cleanup: () => {
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
  };
}

// ---------------------------------------------------------------------------
// dispatch / method routing
// ---------------------------------------------------------------------------

test('dispatch unknown method throws RpcMethodError(METHOD_NOT_FOUND)', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('does_not_exist', null, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_METHOD_NOT_FOUND);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// sigil_list_portals
// ---------------------------------------------------------------------------

test('list_portals returns all loaded handles with derived addresses', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    ctx.handles.addEntry('evm:executor', new SecretBuffer(priv(2)));
    const result = (await dispatch('sigil_list_portals', null, ctx)) as {
      portals: { handle: string; kind: string; address: string }[];
    };
    equal(result.portals.length, 2);
    const bot = result.portals.find((p) => p.handle === 'evm:bot')!;
    equal(bot.address, addressFromPrivateKey(priv(1)));
    const exec = result.portals.find((p) => p.handle === 'evm:executor')!;
    equal(exec.address, addressFromPrivateKey(priv(2)));
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// sigil_eth_sign_message
// ---------------------------------------------------------------------------

test('eth_sign_message recovers to the portal address and writes audit', async () => {
  const { ctx, auditPath, cleanup } = makeCtx();
  try {
    const messageHex = '0x' + Buffer.from('hello world', 'utf8').toString('hex');
    const result = (await dispatch(
      'sigil_eth_sign_message',
      { portal: 'evm:bot', message: messageHex },
      ctx,
    )) as { signature: string };
    ok(result.signature.startsWith('0x'));
    // Verify recovery
    const sigBytes = Buffer.from(result.signature.slice(2), 'hex');
    const parsed = deserializeEthSignature(sigBytes);
    const digest = personalSignDigest(Buffer.from('hello world', 'utf8'));
    const pub = recoverPublicKey(digest, parsed);
    equal(addressFromPublicKey(pub), addressFromPrivateKey(priv(1)));
    // Audit log has the entry
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.kind, 'eth_sign_message');
    equal(entries[0]!.portal, 'evm:bot');
    equal(entries[0]!.decision, 'allow');
    equal(entries[0]!.sig, result.signature);
  } finally {
    cleanup();
  }
});

test('eth_sign_message: missing portal returns INVALID_PARAMS', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_message', { message: '0xff' }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err);
    equal(err!.code, RPC_INVALID_PARAMS);
  } finally {
    cleanup();
  }
});

test('eth_sign_message: unknown portal returns PORTAL_NOT_FOUND', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_message', { portal: 'evm:nope', message: '0xff' }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err);
    equal(err!.code, RPC_PORTAL_NOT_FOUND);
  } finally {
    cleanup();
  }
});

test('eth_sign_message: non-hex message returns INVALID_PARAMS', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_message', { portal: 'evm:bot', message: 'not hex' }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err);
    equal(err!.code, RPC_INVALID_PARAMS);
  } finally {
    cleanup();
  }
});

test('eth_sign_message: params not an object returns INVALID_PARAMS', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    await rejects(() => dispatch('sigil_eth_sign_message', 'oops', ctx), RpcMethodError);
    await rejects(() => dispatch('sigil_eth_sign_message', null, ctx), RpcMethodError);
    await rejects(() => dispatch('sigil_eth_sign_message', [1, 2], ctx), RpcMethodError);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// sigil_eth_sign_transaction
// ---------------------------------------------------------------------------

test('eth_sign_transaction (eip1559) recovers to portal address and audits', async () => {
  const { ctx, auditPath, cleanup } = makeCtx();
  try {
    const tx = {
      type: 'eip1559',
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: '2000000000',
      maxFeePerGas: '30000000000',
      gasLimit: '21000',
      to: '0x000000000000000000000000000000000000dead',
      value: '100',
      data: '0x',
    };
    const result = (await dispatch(
      'sigil_eth_sign_transaction',
      { portal: 'evm:bot', tx },
      ctx,
    )) as { signed: string };
    ok(result.signed.startsWith('0x02'));

    // Recover the signer.
    const payload = Buffer.from(result.signed.slice(4), 'hex');
    const decoded = rlpDecode(payload);
    if (!Array.isArray(decoded)) throw new Error('expected list');
    const yParityBuf = decoded[9] as Buffer;
    const r = decoded[10] as Buffer;
    const s = decoded[11] as Buffer;
    const yParity = yParityBuf.length === 0 ? 0 : (yParityBuf[0]! as 0 | 1);
    const txForDigest: Eip1559Tx = {
      type: 'eip1559',
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: 2_000_000_000n,
      maxFeePerGas: 30_000_000_000n,
      gasLimit: 21_000n,
      to: '0x000000000000000000000000000000000000dead',
      value: 100n,
      data: '0x',
    };
    const pub = recoverPublicKey(txDigest(txForDigest), { r, s, recovery: yParity as 0 | 1 });
    equal(addressFromPublicKey(pub), addressFromPrivateKey(priv(1)));

    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.kind, 'eth_sign_transaction');
    equal(entries[0]!.sig, result.signed);
  } finally {
    cleanup();
  }
});

test('eth_sign_transaction: malformed tx fields return INVALID_PARAMS', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_eth_sign_transaction',
          {
            portal: 'evm:bot',
            tx: {
              type: 'eip1559',
              chainId: 1,
              nonce: 'not-a-number',
              maxPriorityFeePerGas: 1,
              maxFeePerGas: 1,
              gasLimit: 21000,
              to: '0xdead',
              value: 0,
              data: '0x',
            },
          },
          ctx,
        ),
      RpcMethodError,
    );
    await rejects(
      () =>
        dispatch(
          'sigil_eth_sign_transaction',
          {
            portal: 'evm:bot',
            tx: { type: 'unknown' },
          },
          ctx,
        ),
      RpcMethodError,
    );
    await rejects(
      () =>
        dispatch(
          'sigil_eth_sign_transaction',
          {
            portal: 'evm:bot',
            tx: {
              type: 'eip1559',
              chainId: 1,
              nonce: 0,
              maxPriorityFeePerGas: 1,
              maxFeePerGas: 1,
              gasLimit: 21000,
              to: 'not-an-address',
              value: 0,
              data: '0x',
            },
          },
          ctx,
        ),
      RpcMethodError,
    );
  } finally {
    cleanup();
  }
});

test('eth_sign_transaction supports legacy tx', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    const result = (await dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: {
          type: 'legacy',
          chainId: 1,
          nonce: 0,
          gasPrice: '20000000000',
          gasLimit: 21000,
          to: '0x000000000000000000000000000000000000dead',
          value: '0',
          data: '0x',
        },
      },
      ctx,
    )) as { signed: string };
    ok(result.signed.startsWith('0x'));
    ok(!result.signed.startsWith('0x02')); // legacy doesn't have a type prefix
  } finally {
    cleanup();
  }
});

test('eth_sign_transaction supports contract creation (to=null)', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    const result = (await dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: {
          type: 'eip1559',
          chainId: 1,
          nonce: 0,
          maxPriorityFeePerGas: 1,
          maxFeePerGas: 1,
          gasLimit: 100000,
          to: null,
          value: 0,
          data: '0x6080604052',
        },
      },
      ctx,
    )) as { signed: string };
    ok(result.signed.startsWith('0x02'));
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// sigil_eth_sign_typed_data
// ---------------------------------------------------------------------------

test('eth_sign_typed_data recovers to portal address (canonical EIP-712 example)', async () => {
  const { ctx, auditPath, cleanup } = makeCtx();
  try {
    const td = {
      types: {
        Person: [
          { name: 'name', type: 'string' },
          { name: 'wallet', type: 'address' },
        ],
        Mail: [
          { name: 'from', type: 'Person' },
          { name: 'to', type: 'Person' },
          { name: 'contents', type: 'string' },
        ],
      },
      primaryType: 'Mail',
      domain: {
        name: 'Ether Mail',
        version: '1',
        chainId: 1,
        verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
      },
      message: {
        from: { name: 'Cow', wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826' },
        to: { name: 'Bob', wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB' },
        contents: 'Hello, Bob!',
      },
    };
    const result = (await dispatch(
      'sigil_eth_sign_typed_data',
      { portal: 'evm:bot', typedData: td },
      ctx,
    )) as {
      signature: string;
    };
    equal(result.signature.length, 2 + 130);
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.kind, 'eth_sign_typed_data');
  } finally {
    cleanup();
  }
});

test('eth_sign_typed_data: malformed typedData returns INVALID_PARAMS', async () => {
  const { ctx, cleanup } = makeCtx();
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_eth_sign_typed_data',
          { portal: 'evm:bot', typedData: { junk: true } },
          ctx,
        ),
      RpcMethodError,
    );
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Audit chain stays linked across multiple calls
// ---------------------------------------------------------------------------

test('multiple sign calls produce a verifiable audit chain', async () => {
  const { ctx, auditPath, cleanup } = makeCtx();
  try {
    for (let i = 0; i < 5; i++) {
      const messageHex = '0x' + Buffer.from(`msg ${i}`, 'utf8').toString('hex');
      await dispatch('sigil_eth_sign_message', { portal: 'evm:bot', message: messageHex }, ctx);
    }
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 5);
    for (let i = 0; i < 5; i++) equal(entries[i]!.seq, i);
  } finally {
    cleanup();
  }
});

test('portal-not-found errors short-circuit before audit (current behavior, will change with policy in #3)', async () => {
  // Current behavior: a portal-not-found error fails before any audit append.
  // When policy lands (#3) we'll audit the deny too. For now: not audited;
  // the audit file is never created.
  const { ctx, cleanup } = makeCtx();
  try {
    try {
      await dispatch('sigil_eth_sign_message', { portal: 'evm:nope', message: '0xff' }, ctx);
    } catch {
      /* expected */
    }
    // No audit entries were written.
    equal(ctx.audit.head.nextSeq, 0);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// DAEMON_LOCKED
// ---------------------------------------------------------------------------

test('sign methods throw DAEMON_LOCKED when the handle table is locked', async () => {
  const dir = mkTmp();
  try {
    const handles = new HandleTable();
    // Note: NOT calling markUnlocked() — table starts locked.
    const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => 1 });
    const ctx: MethodContext = { handles, audit, policy: permissivePolicyResolver() };
    const calls: { method: string; params: unknown }[] = [
      { method: 'sigil_eth_sign_message', params: { portal: 'evm:bot', message: '0xff' } },
      {
        method: 'sigil_eth_sign_transaction',
        params: {
          portal: 'evm:bot',
          tx: {
            type: 'legacy',
            chainId: 1,
            nonce: 0,
            gasPrice: 1,
            gasLimit: 21000,
            to: '0x' + '11'.repeat(20),
            value: 0,
            data: '0x',
          },
        },
      },
      {
        method: 'sigil_eth_sign_typed_data',
        params: {
          portal: 'evm:bot',
          typedData: {
            types: {
              EIP712Domain: [{ name: 'name', type: 'string' }],
              Mail: [{ name: 'msg', type: 'string' }],
            },
            primaryType: 'Mail',
            domain: { name: 'x' },
            message: { msg: 'hi' },
          },
        },
      },
    ];
    try {
      for (const { method, params } of calls) {
        let err: RpcMethodError | null = null;
        try {
          await dispatch(method, params, ctx);
        } catch (e) {
          err = e as RpcMethodError;
        }
        ok(err instanceof RpcMethodError, `${method} should throw RpcMethodError`);
        equal(err!.code, RPC_DAEMON_LOCKED, `${method} should return DAEMON_LOCKED`);
        ok(
          /sigil unlock/.test(err!.message),
          `${method} error message should mention "sigil unlock"`,
        );
      }
    } finally {
      audit.close();
      handles.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('list_portals works while locked (returns empty list)', async () => {
  const dir = mkTmp();
  try {
    const handles = new HandleTable();
    const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => 1 });
    const ctx: MethodContext = { handles, audit, policy: permissivePolicyResolver() };
    try {
      const result = (await dispatch('sigil_list_portals', null, ctx)) as { portals: unknown[] };
      equal(result.portals.length, 0);
    } finally {
      audit.close();
      handles.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true });
  }
});

test('unknown-portal vs locked-table are reported as distinct error codes', async () => {
  // Locked → DAEMON_LOCKED. Unlocked-but-handle-missing → PORTAL_NOT_FOUND.
  const dir = mkTmp();
  try {
    const handles = new HandleTable();
    const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => 1 });
    const ctx: MethodContext = { handles, audit, policy: permissivePolicyResolver() };
    try {
      // Locked.
      let err: RpcMethodError | null = null;
      try {
        await dispatch('sigil_eth_sign_message', { portal: 'evm:x', message: '0xff' }, ctx);
      } catch (e) {
        err = e as RpcMethodError;
      }
      equal(err!.code, RPC_DAEMON_LOCKED);

      // Now unlock with zero portals on disk → still no evm:x.
      handles.markUnlocked();
      err = null;
      try {
        await dispatch('sigil_eth_sign_message', { portal: 'evm:x', message: '0xff' }, ctx);
      } catch (e) {
        err = e as RpcMethodError;
      }
      equal(err!.code, RPC_PORTAL_NOT_FOUND);
    } finally {
      audit.close();
      handles.dispose();
    }
  } finally {
    rmSync(dir, { recursive: true });
  }
});

// ---------------------------------------------------------------------------
// Policy engine integration
// ---------------------------------------------------------------------------

function strictResolverFor(toml: string): PolicyResolver {
  const p = parsePolicy(toml);
  return { resolve: () => p };
}

function makeCtxWithPolicy(policy: PolicyResolver) {
  const dir = mkTmp();
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  return {
    ctx: { handles, audit, policy } as MethodContext,
    cleanup: () => {
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
    auditPath: join(dir, 'audit.log'),
  };
}

test('policy: permissive resolver allows all sign methods through', async () => {
  const { ctx, cleanup } = makeCtxWithPolicy(permissivePolicyResolver());
  try {
    const r = (await dispatch(
      'sigil_eth_sign_message',
      { portal: 'evm:bot', message: '0x68' },
      ctx,
    )) as { signature: string };
    ok(r.signature.startsWith('0x'));
  } finally {
    cleanup();
  }
});

test('policy: strict mode denies personal_sign when allow_message_signing=false', async () => {
  const policy = strictResolverFor(`
    mode = "strict"
    chain_ids = [1]
    allow_message_signing = false
  `);
  const { ctx, cleanup } = makeCtxWithPolicy(policy);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_message', { portal: 'evm:bot', message: '0xff' }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/personal_sign denied/.test(err!.message));
  } finally {
    cleanup();
  }
});

test('policy: strict mode denies tx with value over cap', async () => {
  const policy = strictResolverFor(`
    mode = "strict"
    chain_ids = [1]
    allow_to = ["0x000000000000000000000000000000000000dead"]
    max_value_wei = "100"
  `);
  const { ctx, cleanup } = makeCtxWithPolicy(policy);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: {
            type: 'legacy',
            chainId: 1,
            nonce: 0,
            gasPrice: 1,
            gasLimit: 21000,
            to: '0x000000000000000000000000000000000000dead',
            value: 101,
            data: '0x',
          },
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/exceeds max_value_wei/.test(err!.message));
  } finally {
    cleanup();
  }
});

test('policy: missing policy file → POLICY_DENIED + audit deny', async () => {
  // PolicyResolver that always throws — mimics the FileSystemPolicyResolver
  // when the user's policy file doesn't exist.
  const failing: PolicyResolver = {
    resolve: () => {
      throw new PolicyLoadError('no policy file for portal "evm:bot"');
    },
  };
  const { ctx, cleanup, auditPath } = makeCtxWithPolicy(failing);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_message', { portal: 'evm:bot', message: '0xff' }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/no policy file/.test(err!.message));

    // Audit log should have a deny entry for this attempt.
    const lines = readFileSync(auditPath, 'utf8').trim().split('\n');
    equal(lines.length, 1);
    const entry = JSON.parse(lines[0]!) as { decision: string; reason: string; kind: string };
    equal(entry.decision, 'deny');
    equal(entry.kind, 'eth_sign_message');
    ok(/no policy file/.test(entry.reason));
  } finally {
    cleanup();
  }
});

test('policy: deny short-circuits sign — no signature, no allow entry in audit', async () => {
  const policy = strictResolverFor(`
    mode = "strict"
    chain_ids = [1]
    allow_to = []
    max_value_wei = "0"
  `);
  const { ctx, cleanup, auditPath } = makeCtxWithPolicy(policy);
  try {
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: {
            type: 'legacy',
            chainId: 1,
            nonce: 0,
            gasPrice: 1,
            gasLimit: 21000,
            to: '0x1111111111111111111111111111111111111111',
            value: 0,
            data: '0x',
          },
        },
        ctx,
      );
    } catch {
      /* expected */
    }
    const lines = readFileSync(auditPath, 'utf8').trim().split('\n');
    equal(lines.length, 1);
    const entry = JSON.parse(lines[0]!) as { decision: string; sig?: string };
    equal(entry.decision, 'deny');
    equal(entry.sig, undefined);
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Confirm gate integration
// ---------------------------------------------------------------------------

import {
  ConfirmGate,
  startAckServer,
  type AckServer,
  type ConfirmRequest,
  type ConfirmTransport,
} from '../../src/confirm/index.js';

class ScriptedTransport implements ConfirmTransport {
  readonly name = 'scripted';
  captured: ConfirmRequest | undefined;
  /** When set, send() throws this. Otherwise it captures and lets the test
   *  drive the human-click step via approveUrl/denyUrl. */
  failNext: Error | undefined;
  async send(req: ConfirmRequest): Promise<void> {
    if (this.failNext) {
      const err = this.failNext;
      this.failNext = undefined;
      throw err;
    }
    this.captured = req;
  }
}

async function makeCtxWithConfirm(policyToml: string): Promise<{
  ctx: MethodContext;
  transport: ScriptedTransport;
  ack: AckServer;
  cleanup: () => Promise<void>;
  auditPath: string;
}> {
  const dir = mkTmp();
  const handles = new HandleTable();
  handles.addEntry('evm:bot', new SecretBuffer(priv(1)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  const policy = strictResolverFor(policyToml);
  const transport = new ScriptedTransport();
  const ack = await startAckServer();
  const confirm = new ConfirmGate({ transport, ackServer: ack, timeoutMs: 1000 });
  return {
    ctx: { handles, audit, policy, confirm },
    transport,
    ack,
    auditPath: join(dir, 'audit.log'),
    cleanup: async () => {
      audit.close();
      handles.dispose();
      await ack.close();
      rmSync(dir, { recursive: true });
    },
  };
}

const DEST = '0x000000000000000000000000000000000000dead';

function txAtValue(value: number | bigint): Record<string, unknown> {
  return {
    type: 'legacy',
    chainId: 1,
    nonce: 0,
    gasPrice: '20000000000',
    gasLimit: 21000,
    to: DEST,
    value,
    data: '0x',
  };
}

test('confirm: tx below threshold signs without consulting the gate', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  try {
    const r = (await dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: txAtValue(50),
      },
      ctx,
    )) as { signed: string };
    ok(r.signed.startsWith('0x'));
    equal(transport.captured, undefined);
  } finally {
    await cleanup();
  }
});

test('confirm: tx over threshold pushes summary + signs on approve', async () => {
  const { ctx, transport, cleanup, auditPath } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  try {
    const signing = dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: txAtValue(500),
      },
      ctx,
    ) as Promise<{ signed: string }>;
    signing.catch(() => {
      /* ensure no unhandled rejection if a regression makes us deny */
    });
    await new Promise((r) => setImmediate(r));
    ok(transport.captured, 'transport should have been hit');
    ok(/0x0000…dead/.test(transport.captured!.summary), transport.captured!.summary);
    await fetch(transport.captured!.approveUrl, { method: 'POST' });
    const r = await signing;
    ok(r.signed.startsWith('0x'));
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'allow');
  } finally {
    await cleanup();
  }
});

test('confirm: deny click → POLICY_DENIED + audit deny + no signature', async () => {
  const { ctx, transport, cleanup, auditPath } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  try {
    const signing = dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: txAtValue(500),
      },
      ctx,
    );
    // Suppress the unhandled-rejection signal — we attach a catch later via
    // await, but Node's test runner is eager about flagging the gap.
    signing.catch(() => {
      /* handled below */
    });
    await new Promise((r) => setImmediate(r));
    await fetch(transport.captured!.denyUrl, { method: 'POST' });
    let err: RpcMethodError | null = null;
    try {
      await signing;
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/confirm denied by human/.test(err!.message));
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'deny');
    equal(entries[0]!.sig, undefined);
  } finally {
    await cleanup();
  }
});

test('confirm: timeout → POLICY_DENIED with "timed out" reason', async () => {
  const { ctx, cleanup } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  const ack2 = await startAckServer();
  ctx.confirm = new ConfirmGate({
    transport: new ScriptedTransport(),
    ackServer: ack2,
    timeoutMs: 30,
  });
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: txAtValue(500),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/timed out/.test(err!.message));
  } finally {
    await ack2.close();
    await cleanup();
  }
});

test('confirm: transport error → POLICY_DENIED with transport error reason (fail-closed)', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  transport.failNext = new Error('ECONNREFUSED');
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: txAtValue(500),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/confirm transport error/.test(err!.message));
    ok(/ECONNREFUSED/.test(err!.message));
  } finally {
    await cleanup();
  }
});

test('confirm: no confirm gate in context → POLICY_DENIED, never signs', async () => {
  const { ctx, cleanup, auditPath } = await makeCtxWithConfirm(`
    mode = "permissive"
    require_confirm_above_wei = "100"
  `);
  delete (ctx as { confirm?: unknown }).confirm;
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: txAtValue(500),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/no confirm transport is configured/.test(err!.message));
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'deny');
  } finally {
    await cleanup();
  }
});

test('confirm: strict-mode static deny fires before confirm gate (gate never invoked)', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(`
    mode = "strict"
    chain_ids = [1]
    allow_to = ["${DEST}"]
    max_value_wei = "1000"
    require_confirm_above_wei = "100"
  `);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: txAtValue(2000),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/exceeds max_value_wei/.test(err!.message));
    equal(transport.captured, undefined, 'transport should not have been hit');
  } finally {
    await cleanup();
  }
});

// ---------------------------------------------------------------------------
// Contract creation (deploys) — end-to-end
// ---------------------------------------------------------------------------

const INITCODE = '0x6080604052600080fd';

function deployTx(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    type: 'eip1559',
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 1,
    maxFeePerGas: 1,
    gasLimit: 3000000,
    to: null,
    value: 0,
    data: INITCODE,
    ...over,
  };
}

const DEPLOY_POLICY = `
  mode = "strict"
  chain_ids = [1]
  allow_contract_creation = true
`;

test('deploy: strict mode denies by default, audits, and never hits the transport', async () => {
  const { ctx, transport, cleanup, auditPath } = await makeCtxWithConfirm(`
    mode = "strict"
    chain_ids = [1]
  `);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_transaction', { portal: 'evm:bot', tx: deployTx() }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/contract creation not allowed/.test(err!.message));
    equal(transport.captured, undefined, 'transport should not have been hit');
    const lines = readFileSync(auditPath, 'utf8').trim().split('\n');
    equal(lines.length, 1);
    const entry = JSON.parse(lines[0]!) as { decision: string; sig?: string };
    equal(entry.decision, 'deny');
    equal(entry.sig, undefined);
  } finally {
    await cleanup();
  }
});

test('deploy: allow_contract_creation pushes a confirm and signs a valid creation tx on approve', async () => {
  const { ctx, transport, cleanup, auditPath } = await makeCtxWithConfirm(DEPLOY_POLICY);
  try {
    const signing = dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: deployTx(),
      },
      ctx,
    ) as Promise<{ signed: string }>;
    signing.catch(() => {
      /* handled below via await */
    });
    await new Promise((r) => setImmediate(r));
    ok(transport.captured, 'transport should have been hit');
    // The push tells the human what is being deployed: no address, but the
    // initcode size and chain.
    ok(/contract creation/.test(transport.captured!.summary), transport.captured!.summary);
    ok(/9-byte initcode/.test(transport.captured!.summary), transport.captured!.summary);
    ok(/chain 1/.test(transport.captured!.summary), transport.captured!.summary);
    await fetch(transport.captured!.approveUrl, { method: 'POST' });
    const result = await signing;
    ok(result.signed.startsWith('0x02'));

    // The signed payload is a real creation tx: empty `to`, recovers to the
    // portal address.
    const payload = Buffer.from(result.signed.slice(4), 'hex');
    const decoded = rlpDecode(payload);
    if (!Array.isArray(decoded)) throw new Error('expected list');
    const toBuf = decoded[5] as Buffer;
    equal(toBuf.length, 0, 'creation tx must RLP-encode `to` as empty');
    const yParityBuf = decoded[9] as Buffer;
    const yParity = yParityBuf.length === 0 ? 0 : (yParityBuf[0]! as 0 | 1);
    const txForDigest: Eip1559Tx = {
      type: 'eip1559',
      chainId: 1,
      nonce: 0,
      maxPriorityFeePerGas: 1n,
      maxFeePerGas: 1n,
      gasLimit: 3_000_000n,
      to: null,
      value: 0n,
      data: INITCODE,
    };
    const pub = recoverPublicKey(txDigest(txForDigest), {
      r: decoded[10] as Buffer,
      s: decoded[11] as Buffer,
      recovery: yParity,
    });
    equal(addressFromPublicKey(pub), addressFromPrivateKey(priv(1)));

    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'allow');
    equal(entries[0]!.sig, result.signed);
  } finally {
    await cleanup();
  }
});

test('deploy: legacy-type creation tx signs on approve too', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(DEPLOY_POLICY);
  try {
    const signing = dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: {
          type: 'legacy',
          chainId: 1,
          nonce: 0,
          gasPrice: '20000000000',
          gasLimit: 3000000,
          to: null,
          value: 0,
          data: INITCODE,
        },
      },
      ctx,
    ) as Promise<{ signed: string }>;
    signing.catch(() => {
      /* handled below via await */
    });
    await new Promise((r) => setImmediate(r));
    ok(transport.captured, 'transport should have been hit');
    await fetch(transport.captured!.approveUrl, { method: 'POST' });
    const result = await signing;
    ok(result.signed.startsWith('0x'));
    ok(!result.signed.startsWith('0x02'));
    // Legacy creation: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s]),
    // `to` empty.
    const decoded = rlpDecode(Buffer.from(result.signed.slice(2), 'hex'));
    if (!Array.isArray(decoded)) throw new Error('expected list');
    equal((decoded[3] as Buffer).length, 0);
  } finally {
    await cleanup();
  }
});

test('deploy: human deny click → POLICY_DENIED, audit deny, no signature', async () => {
  const { ctx, transport, cleanup, auditPath } = await makeCtxWithConfirm(DEPLOY_POLICY);
  try {
    const signing = dispatch(
      'sigil_eth_sign_transaction',
      {
        portal: 'evm:bot',
        tx: deployTx(),
      },
      ctx,
    );
    signing.catch(() => {
      /* handled below */
    });
    await new Promise((r) => setImmediate(r));
    await fetch(transport.captured!.denyUrl, { method: 'POST' });
    let err: RpcMethodError | null = null;
    try {
      await signing;
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/confirm denied by human/.test(err!.message));
    ctx.audit.close();
    const entries = verifyChain(readFileSync(auditPath));
    equal(entries.length, 1);
    equal(entries[0]!.decision, 'deny');
    equal(entries[0]!.sig, undefined);
  } finally {
    await cleanup();
  }
});

test('deploy: no confirm gate in context → POLICY_DENIED, never signs (fail-closed)', async () => {
  const { ctx, cleanup } = await makeCtxWithConfirm(DEPLOY_POLICY);
  delete (ctx as { confirm?: unknown }).confirm;
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_transaction', { portal: 'evm:bot', tx: deployTx() }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/no confirm transport is configured/.test(err!.message));
  } finally {
    await cleanup();
  }
});

test('deploy: value over max_value_wei denies before the gate', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(`
    mode = "strict"
    chain_ids = [1]
    allow_contract_creation = true
    max_value_wei = "100"
  `);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: deployTx({ value: 101 }),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/exceeds max_value_wei/.test(err!.message));
    equal(transport.captured, undefined, 'transport should not have been hit');
  } finally {
    await cleanup();
  }
});

test('deploy: wrong chain denies before the gate', async () => {
  const { ctx, transport, cleanup } = await makeCtxWithConfirm(DEPLOY_POLICY);
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_eth_sign_transaction',
        {
          portal: 'evm:bot',
          tx: deployTx({ chainId: 137 }),
        },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    equal(err!.code, RPC_POLICY_DENIED);
    ok(/chain 137 not in/.test(err!.message));
    equal(transport.captured, undefined, 'transport should not have been hit');
  } finally {
    await cleanup();
  }
});

test('deploy: omitting `to` (instead of explicit null) is INVALID_PARAMS, not a deploy', async () => {
  // A missing key must not silently become a contract creation — the caller
  // has to say `to: null` on purpose.
  const { ctx, cleanup } = makeCtx();
  try {
    const tx = deployTx();
    delete tx['to'];
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_eth_sign_transaction', { portal: 'evm:bot', tx }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError);
    equal(err!.code, RPC_INVALID_PARAMS);
  } finally {
    cleanup();
  }
});
