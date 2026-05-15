import { test } from 'node:test';
import { equal, ok } from 'node:assert/strict';
import {
  type Eip1559Tx,
  type LegacyTx,
  signTransaction,
  txDigest,
} from '../../src/eth/sign-tx.js';
import { rlpDecode } from '../../src/eth/rlp.js';
import { addressFromPublicKey } from '../../src/eth/address.js';
import { recoverPublicKey } from '../../src/eth/secp.js';

const PRIV = Buffer.from('0000000000000000000000000000000000000000000000000000000000000001', 'hex');
const ADDR = '0x7e5f4552091a69125d5dfcb7b8c2659029395bdf';

function hexToBuf(h: string): Buffer {
  const s = h.startsWith('0x') ? h.slice(2) : h;
  return Buffer.from(s, 'hex');
}

function bufFromDecoded(d: unknown): Buffer {
  if (!Buffer.isBuffer(d)) throw new Error('expected buffer in decoded RLP');
  return d;
}

test('signTransaction for legacy tx is 0x-prefixed hex', () => {
  const tx: LegacyTx = {
    type: 'legacy',
    chainId: 1,
    nonce: 0,
    gasPrice: 20_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 1_000_000_000_000_000_000n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x'), 'expected 0x prefix');
  ok(signed.length > 2 + 64, 'expected non-trivial signed payload');
});

test('signed legacy tx recovers to the signer address', () => {
  const tx: LegacyTx = {
    type: 'legacy',
    chainId: 1,
    nonce: 9,
    gasPrice: 20_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 1_000_000_000_000_000_000n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  // Parse: rlp([nonce, gasPrice, gasLimit, to, value, data, v, r, s])
  const decoded = rlpDecode(hexToBuf(signed));
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , , vBuf, rBuf, sBuf] = decoded;
  const v = BigInt('0x' + bufFromDecoded(vBuf).toString('hex'));
  // EIP-155 v = chainId*2 + 35 + recovery → recovery = v - chainId*2 - 35
  const recovery = Number(v - BigInt(tx.chainId as number) * 2n - 35n) as 0 | 1;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('signed EIP-1559 tx starts with 0x02 type prefix', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 2_000_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 100n,
    data: '0x',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x02'), `expected 0x02 prefix, got ${signed.slice(0, 4)}`);
});

test('signed EIP-1559 tx recovers to signer address', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 5,
    maxPriorityFeePerGas: 2_000_000_000n,
    maxFeePerGas: 30_000_000_000n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead',
    value: 100n,
    data: '0xdeadbeef',
  };
  const signed = signTransaction(tx, PRIV);
  // EIP-1559: 0x02 || rlp([chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, yParity, r, s])
  const payload = hexToBuf(signed).subarray(1);
  const decoded = rlpDecode(payload);
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , , , , , yParityBuf, rBuf, sBuf] = decoded;
  const yParity = bufFromDecoded(yParityBuf).length === 0 ? 0 : bufFromDecoded(yParityBuf)[0]!;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery: yParity as 0 | 1,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('contract-creation tx (to=null) is supported', () => {
  const tx: Eip1559Tx = {
    type: 'eip1559',
    chainId: 1,
    nonce: 0,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 100000n,
    to: null,
    value: 0n,
    data: '0x6080604052',
  };
  const signed = signTransaction(tx, PRIV);
  ok(signed.startsWith('0x02'));
  // Recover
  const payload = hexToBuf(signed).subarray(1);
  const decoded = rlpDecode(payload);
  if (!Array.isArray(decoded)) throw new Error('expected list');
  const [, , , , , toBuf, , , , yParityBuf, rBuf, sBuf] = decoded;
  // to should be empty for contract creation
  equal(bufFromDecoded(toBuf).length, 0);
  const yParity = bufFromDecoded(yParityBuf).length === 0 ? 0 : bufFromDecoded(yParityBuf)[0]!;
  const pub = recoverPublicKey(txDigest(tx), {
    r: bufFromDecoded(rBuf),
    s: bufFromDecoded(sBuf),
    recovery: yParity as 0 | 1,
  });
  equal(addressFromPublicKey(pub), ADDR);
});

test('different nonces produce different signatures (so tx is bound to nonce)', () => {
  const base = {
    type: 'eip1559' as const,
    chainId: 1,
    maxPriorityFeePerGas: 1n,
    maxFeePerGas: 1n,
    gasLimit: 21000n,
    to: '0x000000000000000000000000000000000000dead' as const,
    value: 1n,
    data: '0x' as const,
  };
  const a = signTransaction({ ...base, nonce: 0 }, PRIV);
  const b = signTransaction({ ...base, nonce: 1 }, PRIV);
  ok(a !== b);
});
