import { test } from 'node:test';
import { equal, ok, throws, match } from 'node:assert/strict';
import {
  evaluate,
  parsePolicy,
  PolicyLoadError,
  type PolicyRequest,
} from '../../src/policy/index.js';
import { base58Encode } from '../../src/svm/index.js';

const RECIP = base58Encode(new Uint8Array(32).fill(2));

function svmTx(transfers: { to: string; lamports: bigint }[], allDecoded = true): PolicyRequest {
  return {
    kind: 'svm_transaction',
    transfers,
    allDecoded,
    instructionCount: transfers.length || 1,
  };
}

// --- evaluate: confirm thresholds ------------------------------------------

test('evaluate svm: strict transfer above confirm threshold → confirm with SOL summary', () => {
  const p = parsePolicy(
    `mode = "strict"\nchain_ids=[1]\nsvm_allow_to=["${RECIP}"]\nsvm_max_lamports="1000000000"\nrequire_confirm_above_lamports="100000000"`,
  );
  // 0.5 SOL > 0.1 SOL threshold, recipient allowlisted, under cap → confirm.
  const d = evaluate(svmTx([{ to: RECIP, lamports: 500_000_000n }]), p);
  equal(d.kind, 'confirm');
  if (d.kind === 'confirm') match(d.summary, /0\.5 SOL/);
});

test('evaluate svm: strict transfer below confirm threshold → allow', () => {
  const p = parsePolicy(
    `mode = "strict"\nchain_ids=[1]\nsvm_allow_to=["${RECIP}"]\nsvm_max_lamports="1000000000"\nrequire_confirm_above_lamports="100000000"`,
  );
  equal(evaluate(svmTx([{ to: RECIP, lamports: 1n }]), p).kind, 'allow');
});

test('evaluate svm: permissive honours the lamport confirm threshold', () => {
  const p = parsePolicy(`mode = "permissive"\nrequire_confirm_above_lamports="100000000"`);
  equal(evaluate(svmTx([{ to: RECIP, lamports: 200_000_000n }]), p).kind, 'confirm');
  equal(evaluate(svmTx([{ to: RECIP, lamports: 1n }]), p).kind, 'allow');
});

test('evaluate svm: strict undecodable tx → confirm regardless of allowlist', () => {
  const p = parsePolicy(
    `mode = "strict"\nchain_ids=[1]\nsvm_allow_to=["${RECIP}"]\nsvm_max_lamports="1000000000"`,
  );
  const d = evaluate(svmTx([], /*allDecoded*/ false), p);
  equal(d.kind, 'confirm');
  if (d.kind === 'confirm') match(d.summary, /unrecognized Solana tx/);
});

test('evaluate svm: permissive allows an undecodable tx outright (no threshold set)', () => {
  const p = parsePolicy('mode = "permissive"');
  equal(evaluate(svmTx([], false), p).kind, 'allow');
});

// --- loader: validation -----------------------------------------------------

test('loader: rejects svm_allow_to entries that are not valid base58', () => {
  throws(
    () => parsePolicy('mode="strict"\nchain_ids=[1]\nsvm_allow_to=["not-valid-0OIl"]'),
    (e: Error) => e instanceof PolicyLoadError && /not valid base58/.test(e.message),
  );
});

test('loader: rejects svm_allow_to entries that do not decode to 32 bytes', () => {
  // "1" decodes to a single zero byte — valid base58, wrong length.
  throws(
    () => parsePolicy('mode="strict"\nchain_ids=[1]\nsvm_allow_to=["1"]'),
    (e: Error) => e instanceof PolicyLoadError && /32-byte/.test(e.message),
  );
});

test('loader: rejects a confirm threshold that is not below the lamport cap', () => {
  throws(
    () =>
      parsePolicy(
        'mode="strict"\nchain_ids=[1]\nsvm_max_lamports="100"\nrequire_confirm_above_lamports="100"',
      ),
    (e: Error) => e instanceof PolicyLoadError && /must be less than/.test(e.message),
  );
});

test('loader: a permissive policy exposes open SVM defaults', () => {
  const p = parsePolicy('mode = "permissive"');
  equal(p.allowSvmMessageSigning, true);
  ok(Array.isArray(p.svmAllowTo) && p.svmAllowTo.length === 0);
  equal(p.svmMaxLamports, 0n);
});

test('loader: a strict policy defaults SVM to closed', () => {
  const p = parsePolicy('mode = "strict"\nchain_ids = [1]');
  equal(p.allowSvmMessageSigning, false);
  equal(p.svmMaxLamports, 0n);
});
