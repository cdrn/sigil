import { test } from 'node:test';
import { equal, ok, rejects } from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AuditWriter } from '../../src/audit/index.js';
import { SecretBuffer } from '../../src/crypto/index.js';
import {
  dispatch,
  HandleTable,
  RPC_DAEMON_LOCKED,
  RPC_INVALID_PARAMS,
  RPC_INVALID_PAYLOAD,
  RPC_POLICY_DENIED,
  RpcMethodError,
  type MethodContext,
} from '../../src/daemon/index.js';
import {
  MemorySpendLedger,
  parsePolicy,
  type Policy,
  type PolicyResolver,
} from '../../src/policy/index.js';
import type { ConfirmGate } from '../../src/confirm/index.js';
import { base58Decode, base58Encode, getPublicKey, verify } from '../../src/svm/index.js';

function priv(byte: number): Buffer {
  const p = Buffer.alloc(32);
  p[31] = byte;
  return p;
}
const PORTAL = 'evm:bot';
const SECRET = priv(1);
const SVM_PUB = getPublicKey(SECRET); // the portal's Solana pubkey

function constResolver(policy: Policy): PolicyResolver {
  return { resolve: () => policy };
}

function makeCtx(
  policy: Policy,
  confirm?: ConfirmGate,
): { ctx: MethodContext; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-svm-'));
  const handles = new HandleTable();
  handles.addEntry(PORTAL, new SecretBuffer(Buffer.from(SECRET)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  return {
    ctx: { handles, audit, policy: constResolver(policy), ...(confirm ? { confirm } : {}) },
    cleanup: () => {
      audit.close();
      handles.dispose();
      rmSync(dir, { recursive: true });
    },
  };
}

function mockConfirm(kind: 'approved' | 'denied' | 'timeout'): ConfirmGate {
  return { transportName: 'mock', request: async () => ({ kind }) } as unknown as ConfirmGate;
}

const permissive = parsePolicy('mode = "permissive"\n');
function strict(extra: string): Policy {
  return parsePolicy(`mode = "strict"\nchain_ids = [1]\n${extra}`);
}

// --- message builders -------------------------------------------------------

function b64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString('base64');
}

/** Legacy transfer message: signer (account 0) -> recipient (account 1). */
function transferMsg(signer: Uint8Array, recipient: Uint8Array, lamports: bigint): Uint8Array {
  const SYSTEM = new Uint8Array(32);
  const data = new Uint8Array(12);
  data[0] = 2;
  let v = lamports;
  for (let i = 0; i < 8; i++) {
    data[4 + i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return Uint8Array.from([
    1,
    0,
    1, // header (1 required signer)
    3,
    ...signer,
    ...recipient,
    ...SYSTEM, // 3 accounts
    ...new Uint8Array(32), // blockhash
    1, // 1 instruction
    2,
    2,
    0,
    1,
    data.length,
    ...data, // system transfer
  ]);
}

/** A message with one undecodable instruction (program = account 1). */
function unknownMsg(signer: Uint8Array): Uint8Array {
  return Uint8Array.from([
    1,
    0,
    1,
    2,
    ...signer,
    ...new Uint8Array(32).fill(7), // signer + a program key
    ...new Uint8Array(32),
    1,
    1,
    1,
    0,
    3,
    9,
    9,
    9, // ix: programIdIndex=1, accounts=[0], data=[9,9,9]
  ]);
}

const RECIP = new Uint8Array(32).fill(2);
const RECIP_B58 = base58Encode(RECIP);

// --- svm_sign_message -------------------------------------------------------

test('svm_sign_message: permissive signs and the signature verifies', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const msg = Buffer.from('sign in with solana');
    const res = (await dispatch(
      'sigil_svm_sign_message',
      { portal: PORTAL, message: msg.toString('base64') },
      ctx,
    )) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally {
    cleanup();
  }
});

test('svm_sign_message: strict denies unless allow_svm_message_signing', async () => {
  const denyCtx = makeCtx(strict('allow_svm_message_signing = false'));
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_svm_sign_message',
          { portal: PORTAL, message: Buffer.from('x').toString('base64') },
          denyCtx.ctx,
        ),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED,
    );
  } finally {
    denyCtx.cleanup();
  }

  const allowCtx = makeCtx(strict('allow_svm_message_signing = true'));
  try {
    const res = (await dispatch(
      'sigil_svm_sign_message',
      { portal: PORTAL, message: Buffer.from('x').toString('base64') },
      allowCtx.ctx,
    )) as { signature: string };
    ok(res.signature.length > 0);
  } finally {
    allowCtx.cleanup();
  }
});

test('svm_sign_message: rejects non-base64 input', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_message', { portal: PORTAL, message: 'not base64!!' }, ctx),
      (e: RpcMethodError) => e.code === RPC_INVALID_PARAMS,
    );
  } finally {
    cleanup();
  }
});

// --- svm_sign_transaction ---------------------------------------------------

test('svm_sign_transaction: permissive signs a transfer; signature verifies over the message', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const msg = transferMsg(SVM_PUB, RECIP, 1000n);
    const res = (await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(msg) },
      ctx,
    )) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: refuses when the portal is not a required signer', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const notUs = new Uint8Array(32).fill(99);
    const msg = transferMsg(notUs, RECIP, 1000n);
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(msg) }, ctx),
      (e: RpcMethodError) =>
        e.code === RPC_INVALID_PAYLOAD && /not a required signer/.test(e.message),
    );
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: strict allows an in-allowlist transfer within the cap', async () => {
  const { ctx, cleanup } = makeCtx(
    strict(`svm_allow_to = ["${RECIP_B58}"]\nsvm_max_lamports = "1000"`),
  );
  try {
    const res = (await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) },
      ctx,
    )) as { signature: string };
    ok(verify(base58Decode(res.signature), transferMsg(SVM_PUB, RECIP, 1000n), SVM_PUB));
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: strict denies a transfer to a non-allowlisted recipient', async () => {
  const other = base58Encode(new Uint8Array(32).fill(5));
  const { ctx, cleanup } = makeCtx(
    strict(`svm_allow_to = ["${other}"]\nsvm_max_lamports = "1000000"`),
  );
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_svm_sign_transaction',
          { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) },
          ctx,
        ),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /not in svm_allow_to/.test(e.message),
    );
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: strict denies a transfer over the lamport cap', async () => {
  const { ctx, cleanup } = makeCtx(
    strict(`svm_allow_to = ["${RECIP_B58}"]\nsvm_max_lamports = "999"`),
  );
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_svm_sign_transaction',
          { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) },
          ctx,
        ),
      (e: RpcMethodError) =>
        e.code === RPC_POLICY_DENIED && /exceeds svm_max_lamports/.test(e.message),
    );
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: undecodable tx fails closed when no confirm gate', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'));
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_svm_sign_transaction',
          { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) },
          ctx,
        ),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /no confirm transport/.test(e.message),
    );
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: undecodable tx is signed after human confirm approval', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'), mockConfirm('approved'));
  try {
    const msg = unknownMsg(SVM_PUB);
    const res = (await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(msg) },
      ctx,
    )) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally {
    cleanup();
  }
});

test('svm_sign_transaction: undecodable tx is denied when human confirm denies', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'), mockConfirm('denied'));
  try {
    await rejects(
      () =>
        dispatch(
          'sigil_svm_sign_transaction',
          { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) },
          ctx,
        ),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /denied by human/.test(e.message),
    );
  } finally {
    cleanup();
  }
});

// ---------------------------------------------------------------------------
// Rolling-window lamport caps on svm_sign_transaction
// ---------------------------------------------------------------------------

test('svm window caps: decoded transfers accumulate; the breach is denied', async () => {
  const policy = parsePolicy('mode = "permissive"\nsvm_max_lamports_per_hour = "100"\n');
  const { ctx, cleanup } = makeCtx(policy);
  const ledger = new MemorySpendLedger({ now: () => 1_700_000_000_000 });
  ctx.ledger = ledger;
  try {
    const to = new Uint8Array(32).fill(9);
    await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(transferMsg(SVM_PUB, to, 60n)) },
      ctx,
    );
    await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(transferMsg(SVM_PUB, to, 40n)) },
      ctx,
    );
    equal(ledger.spent(PORTAL, 'lamports', 3_600_000), 100n);
    await rejects(
      dispatch(
        'sigil_svm_sign_transaction',
        { portal: PORTAL, message: b64(transferMsg(SVM_PUB, to, 1n)) },
        ctx,
      ),
      /svm_max_lamports_per_hour = 100/,
    );
  } finally {
    cleanup();
  }
});

test('svm window caps: an undecodable instruction cannot be bounded → denied when a lamport cap is set, in both modes', async () => {
  for (const toml of [
    'mode = "permissive"\nsvm_max_lamports_per_day = "1000000000000"\n',
    'mode = "strict"\nchain_ids = [1]\nsvm_max_lamports_per_day = "1000000000000"\n',
  ]) {
    const { ctx, cleanup } = makeCtx(parsePolicy(toml), mockConfirm('approved'));
    ctx.ledger = new MemorySpendLedger();
    try {
      await rejects(
        dispatch(
          'sigil_svm_sign_transaction',
          { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) },
          ctx,
        ),
        /cannot be bounded/,
      );
      equal(ctx.ledger.spent(PORTAL, 'lamports', 3_600_000), 0n);
    } finally {
      cleanup();
    }
  }
  // Without a lamport cap, permissive still allows it (unchanged behaviour).
  const { ctx, cleanup } = makeCtx(
    parsePolicy('mode = "permissive"\nmax_value_per_hour_wei = "1"\n'),
  );
  ctx.ledger = new MemorySpendLedger();
  try {
    await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) },
      ctx,
    );
  } finally {
    cleanup();
  }
});

test('svm_sign_message refuses bytes that parse as a transaction message (cap bypass)', async () => {
  const { ctx, cleanup } = makeCtx(
    parsePolicy('mode = "permissive"\nsvm_max_lamports_per_hour = "0"\n'),
  );
  ctx.ledger = new MemorySpendLedger();
  try {
    const to = new Uint8Array(32).fill(9);
    const txBytes = b64(transferMsg(SVM_PUB, to, 1_000_000_000n));
    await rejects(
      dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: txBytes }, ctx),
      /svm_max_lamports_per_hour/,
    );
    let err: RpcMethodError | null = null;
    try {
      await dispatch('sigil_svm_sign_message', { portal: PORTAL, message: txBytes }, ctx);
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError && err.code === RPC_INVALID_PAYLOAD, String(err));
    ok(/use svm_sign_transaction/.test(err!.message));
    // Ordinary off-chain messages still sign.
    const r = (await dispatch(
      'sigil_svm_sign_message',
      { portal: PORTAL, message: b64(Buffer.from('sign in with solana')) },
      ctx,
    )) as { signature: string };
    ok(typeof r.signature === 'string');
  } finally {
    cleanup();
  }
});

test('svm window caps: wei caps do not constrain lamports and vice versa', async () => {
  const policy = parsePolicy('mode = "permissive"\nmax_value_per_hour_wei = "0"\n');
  const { ctx, cleanup } = makeCtx(policy);
  ctx.ledger = new MemorySpendLedger();
  try {
    const to = new Uint8Array(32).fill(9);
    await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(transferMsg(SVM_PUB, to, 10n ** 12n)) },
      ctx,
    );
  } finally {
    cleanup();
  }
});

/** Same transfer as transferMsg, framed as a v0 message with no address-lookup tables. */
function transferMsgV0(signer: Uint8Array, recipient: Uint8Array, lamports: bigint): Uint8Array {
  const legacy = transferMsg(signer, recipient, lamports);
  return Uint8Array.from([0x80, ...legacy, 0]); // version prefix … + zero ALT lookups
}

test('svm_sign_message refuses a v0 transaction message as well', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const to = new Uint8Array(32).fill(9);
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_svm_sign_message',
        { portal: PORTAL, message: b64(transferMsgV0(SVM_PUB, to, 1n)) },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError && err.code === RPC_INVALID_PAYLOAD, String(err));
    // And the transaction path decodes it (so the refusal isn't a false positive).
    ctx.ledger = new MemorySpendLedger();
    await dispatch(
      'sigil_svm_sign_transaction',
      { portal: PORTAL, message: b64(transferMsgV0(SVM_PUB, to, 1n)) },
      ctx,
    );
  } finally {
    cleanup();
  }
});

test('svm window caps: a tx mixing a decoded transfer with an unknown instruction is unbounded → denied under a cap', async () => {
  const { ctx, cleanup } = makeCtx(
    parsePolicy('mode = "permissive"\nsvm_max_lamports_per_hour = "1000000000"\n'),
  );
  ctx.ledger = new MemorySpendLedger();
  try {
    const to = new Uint8Array(32).fill(9);
    const SYSTEM = new Uint8Array(32);
    const data = new Uint8Array(12);
    data[0] = 2;
    data[4] = 1; // 1 lamport
    // accounts: signer, recipient, system, unknownProgram
    const msg = Uint8Array.from([
      1,
      0,
      2,
      4,
      ...SVM_PUB,
      ...to,
      ...SYSTEM,
      ...new Uint8Array(32).fill(7),
      ...new Uint8Array(32),
      2,
      2,
      2,
      0,
      1,
      data.length,
      ...data, // decoded transfer
      3,
      1,
      0,
      1,
      0xff, // unknown program call
    ]);
    await rejects(
      dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(msg) }, ctx),
      /cannot be bounded/,
    );
    equal(ctx.ledger.spent(PORTAL, 'lamports', 3_600_000), 0n);
  } finally {
    cleanup();
  }
});

test('svm: a confirm approved after the keys were zeroized is refused (zero seed must never sign)', async () => {
  const toKey = new Uint8Array(32).fill(9);
  const policy = parsePolicy(
    `mode = "strict"\nchain_ids = [1]\nrequire_confirm_above_lamports = "0"\nsvm_allow_to = ["${base58Encode(toKey)}"]\nsvm_max_lamports = "1000"\n`,
  );
  let handlesRef: HandleTable | null = null;
  const gate = {
    transportName: 'mock',
    request: async () => {
      handlesRef!.dispose();
      return { kind: 'approved' as const };
    },
  } as unknown as ConfirmGate;
  const { ctx, cleanup } = makeCtx(policy, gate);
  handlesRef = ctx.handles as HandleTable;
  try {
    let err: RpcMethodError | null = null;
    try {
      await dispatch(
        'sigil_svm_sign_transaction',
        { portal: PORTAL, message: b64(transferMsg(SVM_PUB, toKey, 1n)) },
        ctx,
      );
    } catch (e) {
      err = e as RpcMethodError;
    }
    ok(err instanceof RpcMethodError, String(err));
    equal(err!.code, RPC_DAEMON_LOCKED);
  } finally {
    try {
      cleanup();
    } catch {
      /* handles already disposed */
    }
  }
});
