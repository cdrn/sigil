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
  type MethodContext,
  RPC_INVALID_PARAMS,
  RPC_INVALID_PAYLOAD,
  RPC_POLICY_DENIED,
  RpcMethodError,
} from '../../src/daemon/index.js';
import { parsePolicy, type Policy, type PolicyResolver } from '../../src/policy/index.js';
import type { ConfirmGate } from '../../src/confirm/index.js';
import { base58Decode, base58Encode, getPublicKey, verify } from '../../src/svm/index.js';

function priv(byte: number): Buffer { const p = Buffer.alloc(32); p[31] = byte; return p; }
const PORTAL = 'evm:bot';
const SECRET = priv(1);
const SVM_PUB = getPublicKey(SECRET); // the portal's Solana pubkey

function constResolver(policy: Policy): PolicyResolver { return { resolve: () => policy }; }

function makeCtx(policy: Policy, confirm?: ConfirmGate): { ctx: MethodContext; cleanup: () => void } {
  const dir = mkdtempSync(join(tmpdir(), 'sigil-svm-'));
  const handles = new HandleTable();
  handles.addEntry(PORTAL, new SecretBuffer(Buffer.from(SECRET)));
  handles.markUnlocked();
  let now = 1_700_000_000_000;
  const audit = new AuditWriter(join(dir, 'audit.log'), { now: () => ++now });
  return {
    ctx: { handles, audit, policy: constResolver(policy), ...(confirm ? { confirm } : {}) },
    cleanup: () => { audit.close(); handles.dispose(); rmSync(dir, { recursive: true }); },
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

function b64(bytes: Uint8Array): string { return Buffer.from(bytes).toString('base64'); }

/** Legacy transfer message: signer (account 0) -> recipient (account 1). */
function transferMsg(signer: Uint8Array, recipient: Uint8Array, lamports: bigint): Uint8Array {
  const SYSTEM = new Uint8Array(32);
  const data = new Uint8Array(12); data[0] = 2;
  let v = lamports; for (let i = 0; i < 8; i++) { data[4 + i] = Number(v & 0xffn); v >>= 8n; }
  return Uint8Array.from([
    1, 0, 1,                                   // header (1 required signer)
    3, ...signer, ...recipient, ...SYSTEM,     // 3 accounts
    ...new Uint8Array(32),                      // blockhash
    1,                                          // 1 instruction
    2, 2, 0, 1, data.length, ...data,           // system transfer
  ]);
}

/** A message with one undecodable instruction (program = account 1). */
function unknownMsg(signer: Uint8Array): Uint8Array {
  return Uint8Array.from([
    1, 0, 1,
    2, ...signer, ...new Uint8Array(32).fill(7), // signer + a program key
    ...new Uint8Array(32),
    1,
    1, 1, 0, 3, 9, 9, 9,                         // ix: programIdIndex=1, accounts=[0], data=[9,9,9]
  ]);
}

const RECIP = new Uint8Array(32).fill(2);
const RECIP_B58 = base58Encode(RECIP);

// --- svm_sign_message -------------------------------------------------------

test('svm_sign_message: permissive signs and the signature verifies', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const msg = Buffer.from('sign in with solana');
    const res = await dispatch('sigil_svm_sign_message', { portal: PORTAL, message: msg.toString('base64') }, ctx) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally { cleanup(); }
});

test('svm_sign_message: strict denies unless allow_svm_message_signing', async () => {
  const denyCtx = makeCtx(strict('allow_svm_message_signing = false'));
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_message', { portal: PORTAL, message: Buffer.from('x').toString('base64') }, denyCtx.ctx),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED,
    );
  } finally { denyCtx.cleanup(); }

  const allowCtx = makeCtx(strict('allow_svm_message_signing = true'));
  try {
    const res = await dispatch('sigil_svm_sign_message', { portal: PORTAL, message: Buffer.from('x').toString('base64') }, allowCtx.ctx) as { signature: string };
    ok(res.signature.length > 0);
  } finally { allowCtx.cleanup(); }
});

test('svm_sign_message: rejects non-base64 input', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_message', { portal: PORTAL, message: 'not base64!!' }, ctx),
      (e: RpcMethodError) => e.code === RPC_INVALID_PARAMS,
    );
  } finally { cleanup(); }
});

// --- svm_sign_transaction ---------------------------------------------------

test('svm_sign_transaction: permissive signs a transfer; signature verifies over the message', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const msg = transferMsg(SVM_PUB, RECIP, 1000n);
    const res = await dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(msg) }, ctx) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally { cleanup(); }
});

test('svm_sign_transaction: refuses when the portal is not a required signer', async () => {
  const { ctx, cleanup } = makeCtx(permissive);
  try {
    const notUs = new Uint8Array(32).fill(99);
    const msg = transferMsg(notUs, RECIP, 1000n);
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(msg) }, ctx),
      (e: RpcMethodError) => e.code === RPC_INVALID_PAYLOAD && /not a required signer/.test(e.message),
    );
  } finally { cleanup(); }
});

test('svm_sign_transaction: strict allows an in-allowlist transfer within the cap', async () => {
  const { ctx, cleanup } = makeCtx(strict(`svm_allow_to = ["${RECIP_B58}"]\nsvm_max_lamports = "1000"`));
  try {
    const res = await dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) }, ctx) as { signature: string };
    ok(verify(base58Decode(res.signature), transferMsg(SVM_PUB, RECIP, 1000n), SVM_PUB));
  } finally { cleanup(); }
});

test('svm_sign_transaction: strict denies a transfer to a non-allowlisted recipient', async () => {
  const other = base58Encode(new Uint8Array(32).fill(5));
  const { ctx, cleanup } = makeCtx(strict(`svm_allow_to = ["${other}"]\nsvm_max_lamports = "1000000"`));
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) }, ctx),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /not in svm_allow_to/.test(e.message),
    );
  } finally { cleanup(); }
});

test('svm_sign_transaction: strict denies a transfer over the lamport cap', async () => {
  const { ctx, cleanup } = makeCtx(strict(`svm_allow_to = ["${RECIP_B58}"]\nsvm_max_lamports = "999"`));
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(transferMsg(SVM_PUB, RECIP, 1000n)) }, ctx),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /exceeds svm_max_lamports/.test(e.message),
    );
  } finally { cleanup(); }
});

test('svm_sign_transaction: undecodable tx fails closed when no confirm gate', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'));
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) }, ctx),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /no confirm transport/.test(e.message),
    );
  } finally { cleanup(); }
});

test('svm_sign_transaction: undecodable tx is signed after human confirm approval', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'), mockConfirm('approved'));
  try {
    const msg = unknownMsg(SVM_PUB);
    const res = await dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(msg) }, ctx) as { signature: string };
    ok(verify(base58Decode(res.signature), msg, SVM_PUB));
  } finally { cleanup(); }
});

test('svm_sign_transaction: undecodable tx is denied when human confirm denies', async () => {
  const { ctx, cleanup } = makeCtx(strict('svm_allow_to = []'), mockConfirm('denied'));
  try {
    await rejects(
      () => dispatch('sigil_svm_sign_transaction', { portal: PORTAL, message: b64(unknownMsg(SVM_PUB)) }, ctx),
      (e: RpcMethodError) => e.code === RPC_POLICY_DENIED && /denied by human/.test(e.message),
    );
  } finally { cleanup(); }
});
